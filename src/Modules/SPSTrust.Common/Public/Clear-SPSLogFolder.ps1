function Clear-SPSLogFolder {
    <#
        .SYNOPSIS
        Deletes old files from a folder based on a retention window.

        .DESCRIPTION
        Clear-SPSLogFolder removes files older than the requested number of days from
        the specified folder (recursively). The retention window is evaluated against
        each file's LastWriteTime. It is the toolkit's single rotation implementation,
        reused for both the transcript logs (Logs\) and the archived results snapshots
        (Results\history\, via -Extension '*.json').

        A Retention of 0 disables pruning (nothing is deleted). The function emits
        banner lines on stdout so it stays visible inside the Start-Transcript output
        produced by SPSTrust.

        .PARAMETER Path
        Directory to scan. Subdirectories are scanned recursively.

        .PARAMETER Retention
        Number of days to keep. Files older than this are deleted. Defaults to 90 days.
        A value of 0 disables pruning.

        .PARAMETER Extension
        File name pattern to filter on. Defaults to '*.log'.

        .EXAMPLE
        Clear-SPSLogFolder -Path 'D:\Tools\Logs' -Retention 30

        .EXAMPLE
        Clear-SPSLogFolder -Path $historyFolder -Retention 30 -Extension '*.json'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter()]
        [System.UInt32]
        $Retention = 90,

        [Parameter()]
        [System.String]
        $Extension = '*.log'
    )

    if ($Retention -eq 0) {
        Write-Verbose -Message 'Clear-SPSLogFolder: retention disabled (Retention = 0), nothing to prune.'
        return
    }

    if (-not (Test-Path -Path $Path)) {
        return
    }

    $lastWrite = (Get-Date).AddDays(-$Retention)

    $files = Get-ChildItem -Path $Path -Include $Extension -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object -FilterScript { $_.LastWriteTime -le $lastWrite }

    Write-Output '--------------------------------------------------------------'
    if ($files) {
        Write-Output "Cleaning files ($Extension) older than $Retention days in $Path ..."
        foreach ($file in $files) {
            if ($null -ne $file) {
                if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove file')) {
                    Write-Output "Deleting file $($file.FullName) ..."
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }
    else {
        Write-Output "$Path - No files ($Extension) to delete"
    }
    Write-Output '--------------------------------------------------------------'
}
