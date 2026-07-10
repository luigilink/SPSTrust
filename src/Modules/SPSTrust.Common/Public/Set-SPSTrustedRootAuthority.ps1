function Set-SPSTrustedRootAuthority {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.String]
    $CertificateThumbprint,

    [Parameter()]
    [String]
    $CertificateFilePath,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter()]
    [ValidateSet('Present', 'Absent')]
    [System.String]
    $Ensure = 'Present'
  )

  Write-Verbose -Message "Setting SPTrustedRootAuthority '$Name'"
  if ($Ensure -eq 'Present') {
    if (-not ($PSBoundParameters.ContainsKey("CertificateThumbprint")) -and `
        -not($PSBoundParameters.ContainsKey("CertificateFilePath"))) {
      $message = ("At least one of the following parameters must be specified: " + `
          "CertificateThumbprint, CertificateFilePath.")
      throw $message
    }

    if ($PSBoundParameters.ContainsKey("CertificateFilePath") -and `
        -not ($PSBoundParameters.ContainsKey("CertificateThumbprint"))) {
      if (-not (Test-Path -Path $CertificateFilePath)) {
        $message = ("Specified CertificateFilePath does not exist: $CertificateFilePath")
        throw $message
      }
    }
  }

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    if ($params.Ensure -eq 'Absent') {
      Write-Verbose -Message "Removing SPTrustedRootAuthority '$params.Name'"
      Remove-SPTrustedRootAuthority -Identity $params.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    else {
      if ($params.ContainsKey("CertificateFilePath")) {
        Write-Verbose -Message "Importing certificate from CertificateFilePath"
        try {
          $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
          $cert.Import($params.CertificateFilePath)
        }
        catch {
          $message = "An error occured: $($_.Exception.Message)"
          throw $message
        }

        if ($null -eq $cert) {
          $message = "Import of certificate failed."
          throw $message
        }

        if ($params.ContainsKey("CertificateThumbprint")) {
          if (-not $params.CertificateThumbprint.Equals($cert.Thumbprint)) {
            $message = "Imported certificate thumbprint ($($cert.Thumbprint)) does not match expected thumbprint ($($params.CertificateThumbprint))."
            throw $message
          }
        }
      }
      else {
        Write-Verbose -Message "Importing certificate from CertificateThumbprint"
        $cert = Get-Item -Path "CERT:\LocalMachine\My\$($params.CertificateThumbprint)" `
          -ErrorAction SilentlyContinue

        if ($null -eq $cert) {
          $message = "Certificate not found in the local Certificate Store"
          throw $message
        }
      }

      if ($cert.HasPrivateKey) {
        Write-Verbose -Message "Certificate has private key. Removing private key."
        $pubKeyBytes = $cert.Export("cert")
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert2.Import($pubKeyBytes)
        $cert = $cert2
      }

      Write-Verbose -Message "Updating Root Authority"
      New-SPTrustedRootAuthority -Name $params.Name -Certificate $cert
    }
  }
}
