#region Import Modules
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'sps.util.psm1') -Force
#endregion

function Invoke-SPSCommand {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [Object[]]
        $Arguments,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Server
    )

    $VerbosePreference = 'Continue'
    $baseScript = @"
        if (`$null -eq (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue))
        {
            Add-PSSnapin Microsoft.SharePoint.PowerShell
        }

"@

    $invokeArgs = @{
        ScriptBlock = [ScriptBlock]::Create($baseScript + $ScriptBlock.ToString())
    }
    if ($null -ne $Arguments) {
        $invokeArgs.Add("ArgumentList", $Arguments)
    }
    if ($null -eq $Credential) {
        throw 'You need to specify a Credential'
    }
    else {
        Write-Verbose -Message ("Executing using a provided credential and local PSSession " + `
                "as user $($Credential.UserName)")

        # Running garbage collection to resolve issues related to Azure DSC extention use
        [GC]::Collect()

        $session = New-PSSession -ComputerName $Server `
            -Credential $Credential `
            -Authentication CredSSP `
            -Name "Microsoft.SharePoint.PSSession" `
            -SessionOption (New-PSSessionOption -OperationTimeout 0 `
                -IdleTimeout 60000) `
            -ErrorAction Continue

        if ($session) {
            $invokeArgs.Add("Session", $session)
        }

        try {
            return Invoke-Command @invokeArgs -Verbose
        }
        catch {
            throw $_
        }
        finally {
            if ($session) {
                Remove-PSSession -Session $session
            }
        }
    }
}
function Get-SPSServer {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $InstallAccount
    )

    Write-Verbose "Getting SharePoint Servers of Farm '$Server'"
    $result = Invoke-SPSCommand -Credential $InstallAccount `
        -Arguments $PSBoundParameters `
        -Server $Server `
        -ScriptBlock {
        (Get-SPServer | Where-Object -FilterScript { $_.Role -ne 'Invalid' }).Name
    }
    return $result
}

function Clear-SPSLog {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $path,

        [Parameter()]
        [System.UInt32]
        $Retention = 180
    )

    if (Test-Path $path) {
        # Get the current date
        $Now = Get-Date
        # Define LastWriteTime parameter based on $days
        $LastWrite = $Now.AddDays(-$Retention)
        # Get files based on lastwrite filter and specified folder
        $files = Get-Childitem -Path $path -Filter "$($logFileName)*" | Where-Object -FilterScript {
            $_.LastWriteTime -le "$LastWrite"
        }
        if ($files) {
            Write-Output '--------------------------------------------------------------'
            Write-Output "Cleaning log files in $path ..."
            foreach ($file in $files) {
                if ($null -ne $file) {
                    Write-Output "Deleting file $file ..."
                    Remove-Item $file.FullName | out-null
                }
                else {
                    Write-Output 'No more log files to delete'
                    Write-Output '--------------------------------------------------------------'
                }
            }
        }
        else {
            Write-Output '--------------------------------------------------------------'
            Write-Output "$path - No needs to delete log files"
            Write-Output '--------------------------------------------------------------'
        }
    }
    else {
        Write-Output '--------------------------------------------------------------'
        Write-Output "$path does not exist"
        Write-Output '--------------------------------------------------------------'
    }
}
