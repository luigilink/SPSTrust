<#
    .SYNOPSIS
    SPSTrust is a PowerShell script tool to configure trusted farms in your SharePoint environment.

    .DESCRIPTION
    SPSTrust.ps1 is a PowerShell script that configures SharePoint trust relationships between farms.
    Compatible with PowerShell version 5.0 and later.

    .PARAMETER ConfigFile
    Specifies the path to the JSON configuration file, containing details about the application, environment, and certificate paths.

    .PARAMETER FarmAccount
    Specifies the credential for the service account that runs the script.

    .PARAMETER CleanServices
    Optional switch to remove published services on each trusted farm.

    .EXAMPLE
    SPSTrust.ps1 -ConfigFile 'contoso-PROD.json' -FarmAccount (Get-Credential)
    SPSTrust.ps1 -ConfigFile 'contoso-PROD.json' -FarmAccount (Get-Credential) -CleanServices

    .NOTES
    FileName:	SPSTrust.ps1
    Author:		luigilink (Jean-Cyril DROUHIN)
    Date:		October 17, 2024
    Version:	1.1.0

    .LINK
    https://spjc.fr/
    https://github.com/luigilink/SPSTrust
#>
param(
  [Parameter(Position = 1, Mandatory = $true)]
  [ValidateScript({ Test-Path $_ -and $_ -like '*.json' })]
  [System.String]
  $ConfigFile, # Path to the configuration file

  [Parameter(Position = 2, Mandatory = $true)]
  [System.Management.Automation.PSCredential]
  $FarmAccount, # Credential for the FarmAccount

  [Parameter(Position = 3)]
  [switch]
  $CleanServices # Switch parameter to clean services
)

#region Initialization
# Clear the host console
Clear-Host

# Set the window title
$Host.UI.RawUI.WindowTitle = "SPSTrust script running on $env:COMPUTERNAME"

# Define the path to the helper module
$script:HelperModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules'

# Import the helper module
Import-Module -Name (Join-Path -Path $script:HelperModulePath -ChildPath 'util.psm1') -Force

# Ensure the script is running with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  Throw "Administrator rights are required. Please re-run this script as an Administrator."
}

# Load the configuration file
try {
  if (Test-Path $ConfigFile) {
    $jsonEnvCfg = Get-Content $ConfigFile | ConvertFrom-Json
    $Application = $jsonEnvCfg.ApplicationName
    $Environment = $jsonEnvCfg.ConfigurationName
    $certFolder = $jsonEnvCfg.CertFileShared
    $scriptFQDN = $jsonEnvCfg.Domain
    $spFarmsObj = $jsonEnvCfg.Farms
    $spTrustsObj = $jsonEnvCfg.Trusts
  }
  else {
    Throw "Configuration file '$ConfigFile' not found."
  }
}
catch {
  Write-Error "Failed to load configuration file: $_"
  Exit
}

# Define variables
$SPSTrustVersion = '1.0.0'
$getDateFormatted = Get-Date -Format yyyy-MM-dd
$spsTrustFileName = "$($Application)-$($Environment)-$($getDateFormatted)"
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
$scriptRootPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pathLogsFolder = Join-Path -Path $scriptRootPath -ChildPath 'Logs'

# Initialize logs
if (-Not (Test-Path -Path $pathLogsFolder)) {
  New-Item -ItemType Directory -Path $pathLogsFolder -Force
}
$pathLogFile = Join-Path -Path $pathLogsFolder -ChildPath ($spsTrustFileName + '.log')
$DateStarted = Get-Date
$psVersion = ($Host).Version.ToString()

# Start transcript to log the output
Start-Transcript -Path $pathLogFile -IncludeInvocationHeader

# Output the script information
Write-Output '-----------------------------------------------'
Write-Output "| SPSTrust Configuration Script v$SPSTrustVersion |"
Write-Output "| Started on - $DateStarted by $currentUser       |"
Write-Output "| PowerShell Version - $psVersion                 |"
Write-Output '-----------------------------------------------'
#endregion

#region Main Process

# Set power management plan to "High Performance"
Write-Verbose -Message "Setting power management plan to 'High Performance'..."
Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -NoNewWindow

# 1. Exchange trust certificates between the farms
# Export STS and ROOT certificates for each Farm
foreach ($spFarm in $spFarmsObj) {
  $spRootCertPath = "$($certFolder)\$($spFarm.Name)_ROOT.cer"
  $spTargetServer = "$($spFarm.Server).$scriptFQDN"

  try {
    # Check if the ROOT certificate already exists; if not, export it
    if (-Not (Test-Path $spRootCertPath)) {
      Export-SPSTrustedRootAuthority -Name $spFarm.Name -Server $spTargetServer -InstallAccount $FarmAccount -CertificateFilePath $certFolder
      Write-Output "Exported ROOT certificate for $($spFarm.Name)."
    }
    else {
      Write-Output "ROOT certificate for $($spFarm.Name) already exists."
    }
  }
  catch {
    Write-Error "Failed to export ROOT certificate for $($spFarm.Name): $_"
  }

  $spSTSCertPath = "$($certFolder)\$($spFarm.Name)_STS.cer"

  try {
    # Check if the STS certificate already exists; if not, export it
    if (-Not (Test-Path $spSTSCertPath)) {
      Export-SPSSecurityTokenCertificate -Name $spFarm.Name -Server $spTargetServer -InstallAccount $FarmAccount -CertificateFilePath $certFolder
      Write-Output "Exported STS certificate for $($spFarm.Name)."
    }
    else {
      Write-Output "STS certificate for $($spFarm.Name) already exists."
    }
  }
  catch {
    Write-Error "Failed to export STS certificate for $($spFarm.Name): $_"
  }
}

# Establish trust on the publishing farm - Import STS and ROOT certificates
foreach ($spTrust in $spTrustsObj) {
  $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
  $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
  $spRemoteServers = $spTrust.RemoteFarms
  $spServices = $spTrust.Services

  foreach ($spRemoteServer in $spRemoteServers) {
    $spRootCertPath = "$($certFolder)\$($spRemoteServer)_ROOT.cer"
    $currentValues = Get-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" -CertificateFilePath $spRootCertPath -InstallAccount $FarmAccount -Server $spTargetServer

    # Check and establish ROOT trust
    if ($currentValues.Ensure -eq 'Absent') {
      try {
        Set-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" -CertificateFilePath $spRootCertPath -InstallAccount $FarmAccount -Server $spTargetServer
        Write-Output "Trust established with ROOT for $($spRemoteServer)."
      }
      catch {
        Write-Error "Failed to establish ROOT trust for $($spRemoteServer): $_"
      }
    }
    else {
      Write-Verbose -Message "$($spRemoteServer)_ROOT already exists in TrustedRootAuthority"
    }

    # Check and establish STS trust if not a 'Content' service
    if ($spServices -notcontains 'Content') {
      $spSTSCertPath = "$($certFolder)\$($spRemoteServer)_STS.cer"
      $currentValues = Get-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" -CertificateFilePath $spSTSCertPath -InstallAccount $FarmAccount -Server $spTargetServer

      if ($currentValues.Ensure -eq 'Absent') {
        try {
          Set-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" -CertificateFilePath $spSTSCertPath -InstallAccount $FarmAccount -Server $spTargetServer
          Write-Output "Trust established with STS for $($spRemoteServer)."
        }
        catch {
          Write-Error "Failed to establish STS trust for $($spRemoteServer): $_"
        }
      }
      else {
        Write-Verbose -Message "$($spRemoteServer)_STS already exists in TrustedServiceTokenIssuer"
      }
    }
  }

  # 2. On the publishing farm, publish the service application
  foreach ($spService in $spServices) {
    if ($spService -ne 'Content') {
      $currentValues = Get-SPSPublishedServiceApplication -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
      Write-Verbose -Message "Getting URI of service $spService"

      # Store the URI of the service in a variable
      New-Variable -Name "$($spService)_URI" -Value $currentValues.Uri -Force

      if ($currentValues.Ensure -eq 'Absent') {
        Publish-SPSServiceApplication -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
      }
      else {
        Write-Verbose -Message "The service $($spService) is already Published"
      }
    }
  }

  # 3. On the publishing farm, set the permission to the appropriate service applications for the consuming farm.
  foreach ($spService in $spServices) {
    # Set permissions to Published Service Application
    foreach ($spRemoteServer in $spRemoteServers) {
      $spFarmID = Get-SPSFarmId -Server $spRemoteServer -InstallAccount $FarmAccount
      $currentValues = Get-SPSPublishedServiceAppPermission -FarmId "$($spFarmID.Value)" -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount

      # If permissions are not set, set them
      if ($currentValues.Ensure -eq 'Absent') {
        Set-SPSPublishedServiceAppPermission -FarmId "$($spFarmID.Value)" -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
      }
      else {
        Write-Verbose -Message "The Farm $($spRemoteServer) is already added in $($spService)"
      }
    }
  }

  # Set permissions to Application Discovery and Load Balancing Service Application
  foreach ($spRemoteServer in $spRemoteServers) {
    $spFarmID = Get-SPSFarmId -Server $spRemoteServer -InstallAccount $FarmAccount
    $currentValues = Get-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" -Server $spTargetServer -InstallAccount $FarmAccount

    # If permissions are not set, set them
    if ($currentValues.Ensure -eq 'Absent') {
      Set-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" -Server $spTargetServer -InstallAccount $FarmAccount
    }
    else {
      Write-Verbose -Message "The Farm $($spRemoteServer) is already added in Application Discovery Permissions"
    }
  }

  # Connect each published service application on remote farm
  foreach ($spService in $spServices) {
    if ($spService -ne 'Content') {
      $spServicePublishedUri = Get-Variable -Name "$($spService)_URI"
      foreach ($spRemoteServer in $spRemoteServers) {
        $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spRemoteServer }
        $spTargetServer = ($spServer.Server) + '.' + "$($scriptFQDN)"

        # If CleanServices switch is enabled, remove existing service app proxy
        if ($CleanServices) {
          Remove-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
        }
        else {
          $currentValues = Get-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount

          # If the service app proxy is not present, create a new one
          if ($currentValues.Ensure -eq 'Absent') {
            New-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -ServiceUri $spServicePublishedUri.value -InstallAccount $FarmAccount
          }
          else {
            Write-Verbose -Message "The Service Application Proxy $($spService) is already added in Farm $($spRemoteServer)"
          }
        }
      }
    }
  }
}
#endregion

# Clean-Up
Trap { Continue }
$DateEnded = Get-Date
Write-Output '-----------------------------------------------'
Write-Output "| SPSTrust Script Completed                   |"
Write-Output "| Started on  - $DateStarted                  |"
Write-Output "| Ended on    - $DateEnded                    |"
Write-Output '-----------------------------------------------'
Stop-Transcript
Remove-Variable * -ErrorAction SilentlyContinue
Remove-Module * -ErrorAction SilentlyContinue
$error.Clear()
Exit
