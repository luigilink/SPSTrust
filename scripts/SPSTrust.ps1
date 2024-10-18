<#
    .SYNOPSIS
    SPSTrust is a PowerShell script tool to configure trust Farm in your SharePoint environment.

    .DESCRIPTION
    SPSTrust.ps1 is a PowerShell script tool to configure SharePoint Trust.
    It's compatible with PowerShell version 5.0 and later.

    .PARAMETER ConfigFile
    Need parameter ConfigFile, example:
    PS D:\> E:\SCRIPT\SPSTrust.ps1 -ConfigFile 'contoso-PROD.json'

    .PARAMETER FarmAccount
    Need parameter FarmAccount, example:
    PS D:\> E:\SCRIPT\SPSTrust.ps1 -ConfigFile 'contoso-PROD.json' -FarmAccount (Get-Credential)

    .PARAMETER CleanServices
    Need parameter CleanServices to remove connected service application, example:
    PS D:\> E:\SCRIPT\SPSTrust.ps1 -ConfigFile 'contoso-PROD.json' -CleanServices

    .EXAMPLE
    SPSTrust.ps1 -ConfigFile 'contoso-PROD.json'
    SPSTrust.ps1 -ConfigFile 'contoso-PROD.json' -CleanServices

    .NOTES
    FileName:	SPSTrust.ps1
    Author:		luigilink (Jean-Cyril DROUHIN)
    Date:		Ocotober 17, 2024
    Version:	1.0.0

    .LINK
    https://spjc.fr/
    https://github.com/luigilink/SPSTrust
#>
param(
  [Parameter(Position = 1, Mandatory = $true)]
  [System.String]
  $ConfigFile,

  [Parameter(Position = 2)]
  [System.Management.Automation.PSCredential]
  $FarmAccount,

  [Parameter(Position = 3)]
  [switch]
  $CleanServices
)

#region Main
Clear-Host
$Host.UI.RawUI.WindowTitle = "SPSTrust script running on $env:COMPUTERNAME"
$script:HelperModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules'
Import-Module -Name (Join-Path -Path $script:HelperModulePath -ChildPath 'util.psm1') -Force

if (Test-Path $ConfigFile) {
  $jsonEnvCfg = get-content $ConfigFile | ConvertFrom-Json
  $Application = $jsonEnvCfg.ApplicationName
  $Environment = $jsonEnvCfg.ConfigurationName
  $certFolder = $jsonEnvCfg.CertFileShared
  $scriptFQDN = $jsonEnvCfg.Domain
  $spFarmsObj = $jsonEnvCfg.Farms
  $spTrustsObj = $jsonEnvCfg.Trusts
}
else {
  Throw "Missing $ConfigFile"
}

# Define variable
$SPSTrustVersion = '1.0.0'
$getDateFormatted = Get-Date -Format yyyy-MM-dd
$spsTrustFileName = "$($Application)-$($Environment)-$($getDateFormatted)"
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
$scriptRootPath = Split-Path -parent $MyInvocation.MyCommand.Definition
$pathLogsFolder = Join-Path -Path $scriptRootPath -ChildPath 'Logs'

# Initialize required folders
# Check if the path exists
if (-Not (Test-Path -Path $pathLogsFolder)) {
  # If the path does not exist, create the directory
  New-Item -ItemType Directory -Path $pathLogsFolder
}
# Initialize Start-Transcript
$pathLogFile = Join-Path -Path $pathLogsFolder -ChildPath ($spsTrustFileName + '.log')
$DateStarted = Get-date
$psVersion = ($host).Version.ToString()

Start-Transcript -Path $pathLogFile -IncludeInvocationHeader
Write-Output '-----------------------------------------------'
Write-Output "| Automated Script   - Configuration Trust $SPSTrustVersion |"
Write-Output "| Started on         - $DateStarted by $currentUser|"
Write-Output "| PowerShell Version - $psVersion |"
Write-Output '-----------------------------------------------'

# Check Permission Level
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  Write-Warning -Message 'You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!'
  Break
}
else {
  Write-Verbose -Message "Setting power management plan to `"High Performance`"..."
  Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" `
    -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' `
    -NoNewWindow
  
  # Export STS and ROOT certificates for each Farm
  foreach ($spFarm in $spFarmsObj) {
    $spRootCertPath = "$($certFolder)\$($spFarm.Name)_ROOT.cer"
    $spTargetServer = "$($spFarm.Server).$($scriptFQDN)"
    if (Test-Path $spRootCertPath ) {
      Write-Verbose -Message "$($spFarm.Name)_ROOT.cer already exists in file shared"
    }
    else {
      Export-SPSTrustedRootAuthority -Name $spFarm.Name `
        -Server $spTargetServer `
        -InstallAccount $FarmAccount `
        -CertificateFilePath $certFolder
    }

    $spSTSCertPath = "$($certFolder)\$($spFarm.Name)_STS.cer"
    if (Test-Path $spSTSCertPath ) {
      Write-Verbose -Message "$($spFarm.Name)_STS.cer already exists in file shared"
    }
    else {
      Export-SPSSecurityTokenCertificate -Name $spFarm.Name `
        -Server $spTargetServer `
        -InstallAccount $FarmAccount `
        -CertificateFilePath $certFolder
    }

    $getFarmId = Get-SPSFarmId -Server $spTargetServer -InstallAccount $FarmAccount
    New-Variable -Name "$($spFarm.Name)_FarmId" -Value $getFarmId -Force
  }
  # Establishing trust on the publishing farm - Import STS and ROOT certificates
  foreach ($spTrust in $spTrustsObj) {
    $spServer = $jsonEnvCfg.Farms | Where-Object -FilterScript { $_.Name -eq $spTrust.LocalFarm }
    $spTargetServer = "$($spServer.Server).$($scriptFQDN)"
    $spRemoteServers = $spTrust.RemoteFarms
    $spServices = $spTrust.Services
    $AppCode = $spTrust.AppCode
    foreach ($spRemoteServer in $spRemoteServers) {
      $spRootCertPath = "$($certFolder)\$($spRemoteServer)_ROOT.cer"
      $currentValues = Get-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" `
        -CertificateFilePath $spRootCertPath `
        -InstallAccount $FarmAccount `
        -Server $spTargetServer

      if ($currentValues.Ensure -eq 'Absent') {
        Set-SPSTrustedRootAuthority -Name "$($spRemoteServer)_ROOT" `
          -CertificateFilePath $spRootCertPath `
          -InstallAccount $FarmAccount `
          -Server $spTargetServer
      }
      else {
        Write-Verbose -Message "$($spRemoteServer)_ROOT already exists in TrustedRootAuthority"
      }
      if ($spServices -notcontains 'Content' ) {
        $spSTSCertPath = "$($certFolder)\$($spRemoteServer)_STS.cer"
        $currentValues = Get-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" `
          -CertificateFilePath $spSTSCertPath `
          -InstallAccount $FarmAccount `
          -Server $spTargetServer

        if ($currentValues.Ensure -eq 'Absent') {
          Set-SPSTrustedServiceTokenIssuer -Name "$($spRemoteServer)_STS" `
            -CertificateFilePath $spSTSCertPath `
            -InstallAccount $FarmAccount `
            -Server $spTargetServer
        }
        else {
          Write-Verbose -Message "$($spRemoteServer)_STS already exists in TrustedServiceTokenIssuer"
        }
      }
    }

    # Publish Service Application
    foreach ($spService in $spServices) {
      if ($spService -ne 'Content') {
        $currentValues = Get-SPSPublishedServiceApplication -Name $spService `
          -Server $spTargetServer `
          -InstallAccount $FarmAccount
        Write-Verbose -Message "Getting uri of service $spService"
        New-Variable -Name "$($spService)_URI" -Value $currentValues.Uri -Force
        if ($currentValues.Ensure -eq 'Absent') {
          Publish-SPSServiceApplication -Name $spService `
            -Server $spTargetServer `
            -InstallAccount $FarmAccount
        }
        else {
          Write-Verbose -Message "The service $($spService) is already Published"
        }
        # Set permissions to Published Service Application
        foreach ($spRemoteServer in $spRemoteServers) {
          $spFarmID = Get-Variable -Name "$($spRemoteServer)_FarmId"
          $currentValues = Get-SPSPublishedServiceAppPermission -FarmId "$($spFarmID.Value)" `
            -Name $spService `
            -Server $spTargetServer `
            -InstallAccount $FarmAccount
          if ($currentValues.Ensure -eq 'Absent') {
            Set-SPSPublishedServiceAppPermission -FarmId "$($spFarmID.Value)" `
              -Name $spService `
              -Server $spTargetServer `
              -InstallAccount $FarmAccount
          }
          else {
            Write-Verbose -Message "The Farm $($spRemoteServer) is already added in $($spService)"
          }
        }
      }
    }

    # Set permissions to Application Discovery and Load Balancing Service Application
    foreach ($spRemoteServer in $spRemoteServers) {
      $spFarmID = Get-Variable -Name "$($spRemoteServer)_FarmId"
      $currentValues = Get-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" `
        -Server $spTargetServer `
        -InstallAccount $FarmAccount
      if ($currentValues.Ensure -eq 'Absent') {
        Set-SPSTopologyServiceAppPermission -FarmId "$($spFarmID.Value)" `
          -Server $spTargetServer `
          -InstallAccount $FarmAccount
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

          if ($CleanServices) {
            Remove-SPSPublishedServiceAppProxy -Name $spService `
              -Server $spTargetServer `
              -InstallAccount $FarmAccount
          }
          else {
            $currentValues = Get-SPSPublishedServiceAppProxy -Name $spService `
              -Server $spTargetServer `
              -InstallAccount $FarmAccount

            if ($currentValues.Ensure -eq 'Absent') {
              New-SPSPublishedServiceAppProxy -Name $spService `
                -Server $spTargetServer `
                -ServiceUri $spServicePublishedUri.value `
                -InstallAccount $FarmAccount
            }
            else {
              Write-Verbose -Message "The Service Application Proxy $($spService) is already added in Farm $($spRemoteServer)"
            }
          }
        }
      }
    }
  }
  Trap { Continue }

  $DateEnded = Get-date
  Write-Output '-----------------------------------------------'
  Write-Output "| Automated Script - Configuration Trust |"
  Write-Output "| Started on       - $DateStarted |"
  Write-Output "| Completed on     - $DateEnded |"
  Write-Output '-----------------------------------------------'
  Stop-Transcript
  Remove-Variable * -ErrorAction SilentlyContinue;
  Remove-Module *;
  $error.Clear();
  Exit
  #endregion
}
