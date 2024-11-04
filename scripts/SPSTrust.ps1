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
  [ValidateScript({ (Test-Path $_) -and ($_ -like '*.json') })]
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
$scriptRootPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:HelperModulePath = Join-Path -Path $scriptRootPath -ChildPath 'Modules'

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
Write-Output "| SPSTrust Configuration Script v$SPSTrustVersion"
Write-Output "| Started on - $DateStarted by $currentUser"
Write-Output "| PowerShell Version - $psVersion"
Write-Output '-----------------------------------------------'
#endregion

#region Main Process

# Set power management plan to "High Performance"
Write-Verbose -Message "Setting power management plan to 'High Performance'..."
Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -NoNewWindow

# 1. Exchange trust certificates between the farms
# 1.1 Export STS and ROOT certificates for each Farm
foreach ($spFarm in $spFarmsObj) {
  $spRootCertPath = "$($certFolder)\$($spFarm.Name)_ROOT.cer"
  $spSTSCertPath = "$($certFolder)\$($spFarm.Name)_STS.cer"
  $spTargetServer = "$($spFarm.Server).$scriptFQDN"

  # If CleanServices switch is enabled, remove existing ROOT and STS certificates
  if ($CleanServices) {
    try {
      # Check if the ROOT certificate already exists; if not, delete it
      if (Test-Path -Path $spRootCertPath) {
        # Remove the file
        Remove-Item -Path $spRootCertPath -Force
        Write-Output "File '$spRootCertPath' has been removed from the shared folder."
      }
      else {
        Write-Verbose -Message "File '$spRootCertPath' does not exist in the shared folder."
      }
      # Check if the STS certificate already exists; if not, delete it
      if (Test-Path -Path $spSTSCertPath) {
        # Remove the file
        Remove-Item -Path $spSTSCertPath -Force
        Write-Output "File '$spSTSCertPath' has been removed from the shared folder."
      }
      else {
        Write-Verbose -Message "File '$spSTSCertPath' does not exist in the shared folder."
      }
    }
    catch {
      Write-Error "Failed to remove certificates for $($spFarm.Name): $_"
    }
  }
  else {
    try {
      # Check if the ROOT certificate already exists; if not, export it
      if (-Not (Test-Path $spRootCertPath)) {
        Export-SPSTrustedRootAuthority -Name $spFarm.Name -Server $spTargetServer -InstallAccount $FarmAccount -CertificateFilePath $certFolder
        Write-Output "[$($spTargetServer)] Exported ROOT certificate for $($spFarm.Name)."
      }
      else {
        Write-Verbose -Message "[$($spTargetServer)] ROOT certificate for $($spFarm.Name) already exists."
      }
    }
    catch {
      Write-Error "[$($spTargetServer)] Failed to export ROOT certificate for $($spFarm.Name): $_"
    }

    try {
      # Check if the STS certificate already exists; if not, export it
      if (-Not (Test-Path $spSTSCertPath)) {
        Export-SPSSecurityTokenCertificate -Name $spFarm.Name -Server $spTargetServer -InstallAccount $FarmAccount -CertificateFilePath $certFolder
        Write-Output "[$($spTargetServer)] Exported STS certificate for $($spFarm.Name)."
      }
      else {
        Write-Verbose -Message  "[$($spTargetServer)] STS certificate for $($spFarm.Name) already exists."
      }
    }
    catch {
      Write-Error "[$($spTargetServer)] Failed to export STS certificate for $($spFarm.Name): $_"
    }
  }
}

# 1.2 Establish trust on the publishing farm - Import STS and ROOT certificates
foreach ($spTrust in $spTrustsObj) {
  $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
  $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
  $spRemoteServers = $spTrust.RemoteFarms
  $spServices = $spTrust.Services

  foreach ($spRemoteServer in $spRemoteServers) {
    # Get existing ROOT and STS Trust before making changes
    $spRootCertPath = "$($certFolder)\$($spRemoteServer)_ROOT.cer"
    $spSTSCertPath = "$($certFolder)\$($spRemoteServer)_STS.cer"
    try {
      # Retrieve the existing ROOT certificate
      Write-Output "[$($spTargetServer)] Getting Certificate $($spRemoteServer)_ROOT"
      $getSPTrustedRootCert = Get-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" -CertificateFilePath $spRootCertPath -InstallAccount $FarmAccount -Server $spTargetServer
      # Retrieve the existing STS certificate
      Write-Output "[$($spTargetServer)] Getting Certificate $($spRemoteServer)_STS"
      $getSPTrustedSTSCert = Get-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" -CertificateFilePath $spSTSCertPath -InstallAccount $FarmAccount -Server $spTargetServer
    }
    catch {
      # Handle errors during retrieval of ROOT and STS certificates
      Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to get ROOT | STS trust for $($spRemoteServer)
Exception: $_
"@
    }

    # If CleanServices switch is enabled, remove existing ROOT and STS certificates
    if ($CleanServices) {
      # Check and remove ROOT trust if needed
      if ($getSPTrustedRootCert.Ensure -eq 'Present') {
        try {
          # Remove the existing ROOT trust
          Set-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" -InstallAccount $FarmAccount -Server $spTargetServer -Ensure 'Absent'
          Write-Output "[$($spTargetServer)] Trust established with ROOT removed for $($spRemoteServer)."
        }
        catch {
          # Handle errors during removal of ROOT trust
          Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to remove ROOT trust for $($spRemoteServer)
Exception: $_
"@
        }
      }
      else {
        # Log if ROOT trust is not present
        Write-Verbose -Message "[$($spTargetServer)] $($spRemoteServer)_ROOT not present in TrustedRootAuthority"
      }

      # Check and remove STS trust if needed
      if ($getSPTrustedSTSCert.Ensure -eq 'Present') {
        try {
          # Remove the existing STS trust
          Set-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" -InstallAccount $FarmAccount -Server $spTargetServer -Ensure 'Absent'
          Write-Output "[$($spTargetServer)] Trust established with STS removed for $($spRemoteServer)."
        }
        catch {
          # Handle errors during removal of STS trust
          Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to remove STS trust for $($spRemoteServer)
Exception: $_
"@
        }
      }
      else {
        # Log if STS trust is not present
        Write-Verbose -Message "[$($spTargetServer)] $($spRemoteServer)_STS not present in TrustedServiceTokenIssuer"
      }
    }
    else {
      # Check and establish ROOT trust
      if ($getSPTrustedRootCert.Ensure -eq 'Absent') {
        try {
          # Establish the ROOT trust
          Set-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" -CertificateFilePath $spRootCertPath -InstallAccount $FarmAccount -Server $spTargetServer
          Write-Output "[$($spTargetServer)] Trust established with ROOT for $($spRemoteServer)."
        }
        catch {
          # Handle errors during establishment of ROOT trust
          Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to establish ROOT trust for $($spRemoteServer)
Exception: $_
"@
        }
      }
      else {
        # Log if ROOT trust already exists
        Write-Verbose -Message "[$($spTargetServer)] $($spRemoteServer)_ROOT already exists in TrustedRootAuthority"
      }

      # Check and establish STS trust if not a 'Content' service
      if ($spServices -notcontains 'Content') {
        if ($getSPTrustedSTSCert.Ensure -eq 'Absent') {
          try {
            # Establish the STS trust
            Set-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" -CertificateFilePath $spSTSCertPath -InstallAccount $FarmAccount -Server $spTargetServer
            Write-Output "[$($spTargetServer)] Trust established with STS for $($spRemoteServer)."
          }
          catch {
            # Handle errors during establishment of STS trust
            Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to establish STS trust for $($spRemoteServer)
Exception: $_
"@
          }
        }
        else {
          # Log if STS trust already exists
          Write-Verbose -Message "[$($spTargetServer)] $($spRemoteServer)_STS already exists in TrustedServiceTokenIssuer"
        }
      }
    }
  }
}

# 2. On the publishing farm, publish the service application
foreach ($spTrust in $spTrustsObj) {
  $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
  $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
  $spServices = $spTrust.Services

  foreach ($spService in $spServices) {
    # Skip the 'Content' service
    if ($spService -ne 'Content') {
      # Get the current values of the service application
      $currentValues = Get-SPSPublishedServiceApplication -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
      Write-Output "[$($spTargetServer)] Getting URI of service $spService"

      # Store the URI of the service in a variable
      New-Variable -Name "$($spService)_URI" -Value $currentValues.Uri -Force

      # Store the TYPE of the service in a variable
      New-Variable -Name "$($spService)_TYPE" -Value $currentValues.Type -Force

      # If CleanServices switch is enabled, disable the publishing of the service application
      if ($CleanServices) {
        if ($currentValues.Ensure -eq 'Present') {
          try {
            # Unpublish the service application
            Publish-SPSServiceApplication -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount -Ensure 'Absent'
          }
          catch {
            Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to unpublish the service $($spService)
Exception: $_
"@
          }
        }
        else {
          Write-Verbose -Message "[$($spTargetServer)] The service $($spService) is already Unpublished."
        }
      }
      else {
        if ($currentValues.Ensure -eq 'Absent') {
          try {
            # Publish the service application
            Publish-SPSServiceApplication -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
          }
          catch {
            Write-Error -Message @"
Target Server: $($spTargetServer)
Failed to publish the service $($spService)
Exception: $_
"@
          }
        }
        else {
          Write-Verbose -Message "[$($spTargetServer)] The service $($spService) is already Published."
        }
      }
    }
  }
}

# 3. On the publishing farm, set the permission to the appropriate service applications for the consuming farm.
foreach ($spTrust in $spTrustsObj) {
  $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
  $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
  $spRemoteFarms = $spTrust.RemoteFarms
  $spServices = $spTrust.Services

  # 3.1 Set permissions to Application Discovery and Load Balancing Service Application
  foreach ($spRemoteFarm in $spRemoteFarms) {
    # Get the Farm ID for the remote server
    try {
      $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spRemoteFarm }
      $spRemoteServer = "$($spServer.Server).$($scriptFQDN)"
      Write-Output "[$($spRemoteServer)] Getting GUID property of SPFarm Object"
      $spFarmID = Get-SPSFarmId -Server $spRemoteServer -InstallAccount $FarmAccount
    }
    catch {
      Write-Error -Message @"
Target Server: $($spRemoteServer)
Failed to get Farm GUID
Exception: $_
"@
    }

    # Get the current permissions for the Farm ID on the target server
    try {
      Write-Output "[$($spTargetServer)] Getting Permissions of Topology Service for SPFarm: $($spRemoteFarm)"
      $currentValues = Get-SPSTopologyServiceAppPermission -FarmId "$($spFarmID)" -Server $spTargetServer -InstallAccount $FarmAccount
    }
    catch {
      Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: 'Application Discovery and Load Balancing Service Application'
Failed to get current permissions for the Farm: $spRemoteFarm
Farm remote ID: $($spFarmID)
Exception: $_
"@
    }

    # If the CleanServices switch is enabled, Revoke permissions of Application Discovery and Load Balancing Service Application
    if ($CleanServices) {
      if ($currentValues.Ensure -eq 'Present') {
        try {
          # Revoke permissions added in Application Discovery and Load Balancing Service Application
          Write-Output "[$($spTargetServer)] Revoking Permissions of Topology Service for SPFarm: $($spRemoteFarm)"
          Set-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" -Server $spTargetServer -InstallAccount $FarmAccount -Ensure 'Absent'
        }
        catch {
          Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: 'Application Discovery and Load Balancing Service Application'
Failed to revoke permissions for Farm: $($spRemoteFarm)
Exception: $_
"@
        }
      }
      else {
        Write-Verbose -Message @"
The Farm $($spRemoteFarm) is already revoked in Application Discovery Permissions.
Please verify the settings and ensure that all configurations are correct.
"@
      }
    }
    else {
      try {
        # If permissions are not set, set them
        if ($currentValues.Ensure -eq 'Absent') {
          Write-Output "[$($spTargetServer)] Granting Permissions of Topology Service for SPFarm: $($spRemoteFarm)"
          Set-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" -Server $spTargetServer -InstallAccount $FarmAccount
        }
        else {
          Write-Verbose -Message @"
The Farm $($spRemoteFarm) is already granted in Application Discovery Permissions.
Please verify the settings and ensure that all configurations are correct.
"@
        }
      }
      catch {
        Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: 'Application Discovery and Load Balancing Service Application'
Failed to grant permissions for Farm: $($spRemoteFarm)
Exception: $_
"@
      }
    }
  }
  # 3.2 Set permission to a published service application for a consuming farm
  foreach ($spService in $spServices) {
    # Skip the 'Content' service
    if ($spService -ne 'Content') {
      foreach ($spRemoteFarm in $spRemoteFarms) {
        # Get the Farm ID for the remote server
        try {
          $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spRemoteFarm }
          $spRemoteServer = "$($spServer.Server).$($scriptFQDN)"
          Write-Output "[$($spRemoteServer)] Getting GUID property of SPFarm Object"
          $spFarmID = Get-SPSFarmId -Server $spRemoteServer -InstallAccount $FarmAccount
        }
        catch {
          Write-Error -Message @"
Target Server: $($spRemoteServer)
Failed to get Farm GUID
Exception: $_
"@
        }

        # Get the current permissions for the Farm ID on the service application
        try {
          Write-Output "[$($spTargetServer)] Getting Permissions of '$($spService)' for SPFarm: $($spRemoteFarm)"
          $currentValues = Get-SPSPublishedServiceAppPermission -FarmId "$($spFarmID)" -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
        }
        catch {
          Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: $($spService)
Failed to get current permissions for the Farm: $spRemoteFarm
Farm remote ID: $($spFarmID)
Exception: $_
"@
        }

        # If the CleanServices switch is enabled, Revoke permissions of Desired Service Application
        if ($CleanServices) {
          if ($currentValues.Ensure -eq 'Present') {
            try {
              # Revoke permissions added in Application Discovery and Load Balancing Service Application
              Write-Output "[$($spTargetServer)] Revoking Permissions of '$($spService)' for SPFarm: $($spRemoteFarm)"
              Set-SPSPublishedServiceAppPermission -FarmId "$($spFarmID)" -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount -Ensure 'Absent'
            }
            catch {
              Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: $($spService)
Failed to revoke permissions for Farm: $($spRemoteFarm)
Farm remote ID: $($spFarmID)
Exception: $_
"@
            }
          }
          else {
            Write-Verbose -Message @"
The Farm $($spRemoteFarm) is already revoked for service '$($spService)'.
Please verify the settings and ensure that all configurations are correct.
"@
          }
        }
        else {
          # If permissions are not set, set them
          try {
            if ($currentValues.Ensure -eq 'Absent') {
              Write-Output "[$($spTargetServer)] Granting Permissions of '$($spService)' for SPFarm: $($spRemoteFarm)"
              Set-SPSPublishedServiceAppPermission -FarmId "$($spFarmID)" -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
            }
            else {
              Write-Verbose -Message @"
The Farm $($spRemoteFarm) is already granted for service '$($spService)'.
Please verify the settings and ensure that all configurations are correct.
"@
            }
          }
          catch {
            Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application: $($spService)
Failed to grant permissions for Farm: $($spRemoteFarm)
Farm remote ID: $($spFarmID)
Exception: $_
"@
          }
        }
      }
    }
  }
}

# 4. Connect each published service application on remote farm
foreach ($spTrust in $spTrustsObj) {
  $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
  $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
  $spRemoteFarms = $spTrust.RemoteFarms
  $spServices = $spTrust.Services

  foreach ($spService in $spServices) {
    # Skip the 'Content' service
    if ($spService -ne 'Content') {
      # Retrieve the URI and Type for the current service
      $spServicePublishedUri = Get-Variable -Name "$($spService)_URI"
      $spServicePublishedType = Get-Variable -Name "$($spService)_TYPE"

      # Loop through each remote server in the $spRemoteServers array
      foreach ($spRemoteFarm in $spRemoteFarms) {
        # Find the server configuration for the current remote server
        $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spRemoteFarm }
        $spRemoteServer = "$($spServer.Server).$($scriptFQDN)"

        try {
          # Get the current service application proxy values for the target server
          $currentValues = Get-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
        }
        catch {
          # Log an error if unable to get the service application proxy
          Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application Name: $($spService)
Failed to get service application proxy for Farm: $($spRemoteServer)
Exception: $_
"@
        }
        # If CleanServices switch is enabled, remove existing service app proxy
        if ($CleanServices) {
          try {
            # If the service app proxy is present, remove it
            if ($currentValues.Ensure -eq 'Present') {
              Remove-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -InstallAccount $FarmAccount
            }
            else {
              Write-Verbose -Message "The Service Application Proxy $($spService) is already removed in Farm $($spRemoteServer)"
            }
          }
          catch {
            # Log an error if unable to remove the service application proxy
            Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application Name: $($spService)
Service Application Uri: $($spServicePublishedUri)
Service Application Type: $($spServicePublishedType)
Failed to remove service application proxy for Farm: $($spRemoteServer)
Exception: $_
"@
          }
        }
        else {
          try {
            # If the service app proxy is not present, create a new one
            if ($currentValues.Ensure -eq 'Absent') {
              New-SPSPublishedServiceAppProxy -Name $spService -Server $spTargetServer -ServiceUri $spServicePublishedUri.value -InstallAccount $FarmAccount -ServiceType $spServicePublishedType
            }
            else {
              Write-Verbose -Message "The Service Application Proxy $($spService) is already added in Farm $($spRemoteServer)"
            }
          }
          catch {
            # Log an error if unable to add the service application proxy
            Write-Error -Message @"
Target Server: $($spTargetServer)
Service Application Name: $($spService)
Service Application Uri: $($spServicePublishedUri)
Service Application Type: $($spServicePublishedType)
Failed to add service application proxy for Farm: $($spRemoteServer)
Exception: $_
"@
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
Write-Output "| SPSTrust Script Completed"
Write-Output "| Started on  - $DateStarted"
Write-Output "| Ended on    - $DateEnded"
Write-Output '-----------------------------------------------'
Stop-Transcript
Remove-Variable * -ErrorAction SilentlyContinue
Remove-Module * -ErrorAction SilentlyContinue
$error.Clear()
Exit
