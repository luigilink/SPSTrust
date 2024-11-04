#region Import Modules
# Import the custom module 'sps.util.psm1' from the script's directory
$scriptModulePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Import-Module -Name (Join-Path -Path $scriptModulePath -ChildPath 'sps.util.psm1') -Force
#endregion

function Invoke-SPSCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential, # Credential to be used for executing the command
        [Parameter()]
        [Object[]]
        $Arguments, # Optional arguments for the script block
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock, # Script block containing the commands to execute
        [Parameter(Mandatory = $true)]
        [System.String]
        $Server # Target server where the commands will be executed
    )
    $VerbosePreference = 'Continue'
    # Base script to ensure the SharePoint snap-in is loaded
    $baseScript = @"
    if (`$null -eq (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue))
    {
        Add-PSSnapin Microsoft.SharePoint.PowerShell
    }
"@

    $invokeArgs = @{
        ScriptBlock = [ScriptBlock]::Create($baseScript + $ScriptBlock.ToString())
    }
    # Add arguments if provided
    if ($null -ne $Arguments) {
        $invokeArgs.Add("ArgumentList", $Arguments)
    }
    # Ensure a credential is provided
    if ($null -eq $Credential) {
        throw 'You need to specify a Credential'
    }
    else {
        Write-Verbose -Message ("Executing using a provided credential and local PSSession " + "as user $($Credential.UserName)")
        # Running garbage collection to resolve issues related to Azure DSC extension use
        [GC]::Collect()
        # Create a new PowerShell session on the target server using the provided credentials
        $session = New-PSSession -ComputerName $Server `
            -Credential $Credential `
            -Authentication CredSSP `
            -Name "Microsoft.SharePoint.PSSession" `
            -SessionOption (New-PSSessionOption -OperationTimeout 0 -IdleTimeout 60000) `
            -ErrorAction Continue

        # Add the session to the invocation arguments if the session is created successfully
        if ($session) {
            $invokeArgs.Add("Session", $session)
        }
        try {
            # Invoke the command on the target server
            return Invoke-Command @invokeArgs -Verbose
        }
        catch {
            throw $_ # Throw any caught exceptions
        }
        finally {
            # Remove the session to clean up
            if ($session) {
                Remove-PSSession -Session $session
            }
        }
    }
}

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

function Clear-SPSLog {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $path, # Path to the log files
        [Parameter()]
        [System.UInt32]
        $Retention = 180 # Number of days to retain log files
    )
    # Check if the log file path exists
    if (Test-Path $path) {
        # Get the current date
        $Now = Get-Date
        # Define LastWriteTime parameter based on $Retention
        $LastWrite = $Now.AddDays(-$Retention)
        # Get files based on last write filter and specified folder
        $files = Get-ChildItem -Path $path -Filter "$($logFileName)*" | Where-Object -FilterScript {
            $_.LastWriteTime -le "$LastWrite"
        }
        # If files are found, proceed to delete them
        if ($files) {
            Write-Output '--------------------------------------------------------------'
            Write-Output "Cleaning log files in $path ..."
            foreach ($file in $files) {
                if ($null -ne $file) {
                    Write-Output "Deleting file $file ..."
                    Remove-Item $file.FullName | Out-Null
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
