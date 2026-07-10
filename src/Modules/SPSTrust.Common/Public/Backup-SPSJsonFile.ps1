function Backup-SPSJsonFile {
    <#
        .SYNOPSIS
        Archives an existing results JSON snapshot into a history folder before it is overwritten.

        .DESCRIPTION
        Backup-SPSJsonFile copies the file at -Path into -HistoryFolder, appending a
        timestamp to the file name (e.g. CONTOSO-PROD-SPSE-20260709-1615.json). The
        original file is left untouched so the caller can overwrite it with a fresh
        audit afterwards.

        The function does not perform retention/rotation itself: call
        Clear-SPSLogFolder -Extension '*.json' on the history folder to prune old
        snapshots, reusing the toolkit's single rotation implementation.

        Returns the full path of the backup that was created, or $null when -Path does
        not exist (first run, nothing to archive).

        .PARAMETER Path
        The results JSON file about to be overwritten.

        .PARAMETER HistoryFolder
        Destination folder for the timestamped copy. Created if missing.

        .PARAMETER TimeStamp
        Timestamp string injected into the backup file name. Defaults to the current
        date/time as yyyyMMdd-HHmm. Exposed mainly for deterministic testing.

        .EXAMPLE
        $previous = Backup-SPSJsonFile -Path $pathJsonFile -HistoryFolder $historyFolder
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.String]
        $HistoryFolder,

        [Parameter()]
        [System.String]
        $TimeStamp = (Get-Date -Format yyyyMMdd-HHmm)
    )

    if (-not (Test-Path -Path $Path)) {
        Write-Verbose -Message "Backup-SPSJsonFile: no existing file to archive at '$Path'."
        return $null
    }

    if (-not (Test-Path -Path $HistoryFolder)) {
        $null = New-Item -Path $HistoryFolder -ItemType Directory -Force
    }

    $leaf = Split-Path -Path $Path -Leaf
    $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $extension = [System.IO.Path]::GetExtension($leaf)
    $backupName = "$name-$TimeStamp$extension"
    $backupPath = Join-Path -Path $HistoryFolder -ChildPath $backupName

    Copy-Item -Path $Path -Destination $backupPath -Force
    Write-Verbose -Message "Backup-SPSJsonFile: archived '$Path' to '$backupPath'."

    return $backupPath
}
