function Get-SPSServer {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Server, # Name of the SharePoint server
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $InstallAccount # Credential for accessing the SharePoint server
    )
    Write-Verbose "Getting SharePoint Servers of Farm '$Server'"
    # Use the Invoke-SPSCommand function to get SharePoint servers
    $result = Invoke-SPSCommand -Credential $InstallAccount `
        -Arguments $PSBoundParameters `
        -Server $Server `
        -ScriptBlock {
            (Get-SPServer | Where-Object -FilterScript { $_.Role -ne 'Invalid' }).Name
    }
    return $result
}

