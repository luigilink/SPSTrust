function Export-SPSTrustedRootAuthority {
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
    [String]
    $CertificateFilePath,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Exporting SPTrustedRootAuthority '$Name'"

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]
    $trustType = 'ROOT'
    $certPath = "$($params.CertificateFilePath)\$($params.Name)_$($trustType).cer"
    $certRoot = Get-SPCertificateAuthority -ErrorAction SilentlyContinue

    if ($null -eq $certRoot) {
      $message = "ROOT Certificate not found in Farm $params.Name"
      throw $message
    }
    else {
      $spRootCertificate = $certRoot.RootCertificate
      [byte[]]$rawcert = $spRootCertificate.RawData

      Write-Verbose -Message "Saving SPTrustedRootAuthority to '$certPath'"
      $rawcert | Set-Content -Path $certPath -Encoding Byte;
    }
  }
}
