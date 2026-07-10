function Export-SPSTrustReport {
    <#
        .SYNOPSIS
        Renders a trust status object (or results JSON file) into a self-contained HTML report.

        .DESCRIPTION
        Export-SPSTrustReport takes the object produced by Get-SPSTrustStatus - either
        passed directly with -Status, or read from a results JSON file with -InputFile -
        and writes a single self-contained HTML file (no external CSS/JS/CDN, so it opens
        offline on a SharePoint server).

        The report shows:
        - a metadata line (application, environment, domain, generation time, version),
        - summary cards (total relationships, and Present / Absent / N/A counts computed
          across every status cell), and
        - an interactive "trust matrix" table: one row per publishing-farm / consuming-farm
          / service, with a status "pill" for each trust dimension (RootTrust, StsTrust,
          Published, TopologyPermission, ServiceAppPermission, Proxy). The table supports
          a search box and click-to-sort headers via Get-SPSReportHtmlScript.

        Returns the full path of the HTML file that was written.

        .PARAMETER Status
        The status object returned by Get-SPSTrustStatus.

        .PARAMETER InputFile
        Path to a results JSON file previously produced from a status object. Mutually
        exclusive with -Status.

        .PARAMETER OutputPath
        Full path of the HTML file to write.

        .EXAMPLE
        Export-SPSTrustReport -Status $status -OutputPath 'D:\Tools\Reports\CONTOSO-PROD.html'

        .EXAMPLE
        Export-SPSTrustReport -InputFile 'D:\Tools\Results\CONTOSO-PROD.json' -OutputPath 'D:\Tools\Reports\CONTOSO-PROD.html'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Status')]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Status')]
        [System.Object]
        $Status,

        [Parameter(Mandatory = $true, ParameterSetName = 'InputFile')]
        [System.String]
        $InputFile,

        [Parameter(Mandatory = $true)]
        [System.String]
        $OutputPath
    )

    if ($PSCmdlet.ParameterSetName -eq 'InputFile') {
        if (-not (Test-Path -Path $InputFile)) {
            throw "Export-SPSTrustReport: input file '$InputFile' not found."
        }
        $Status = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
    }

    $rows = @($Status.Rows)

    # Status dimensions rendered as pills, in column order.
    $dimensions = @(
        @{ Field = 'RootTrust'; Label = 'ROOT' }
        @{ Field = 'StsTrust'; Label = 'STS' }
        @{ Field = 'Published'; Label = 'Published' }
        @{ Field = 'TopologyPermission'; Label = 'Topology' }
        @{ Field = 'ServiceAppPermission'; Label = 'SA Perm' }
        @{ Field = 'Proxy'; Label = 'Proxy' }
    )

    # Compute summary counts across every status cell.
    $presentCount = 0
    $absentCount = 0
    $naCount = 0
    $errorCount = 0
    foreach ($row in $rows) {
        foreach ($dim in $dimensions) {
            switch ("$($row.$($dim.Field))") {
                'Present' { $presentCount++ }
                'Absent' { $absentCount++ }
                'N/A' { $naCount++ }
                'Error' { $errorCount++ }
            }
        }
    }

    # Build a status pill.
    function Get-Pill {
        param([System.String] $Value)
        $safe = ConvertTo-SPSHtmlEncoded -Value $Value
        switch ($Value) {
            'Present' { return "<span class=`"pill pill-present`">$safe</span>" }
            'Absent' { return "<span class=`"pill pill-absent`">$safe</span>" }
            'Error' { return "<span class=`"pill pill-absent`">$safe</span>" }
            default { return "<span class=`"pill pill-na`">$safe</span>" }
        }
    }

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.Append((Get-SPSReportHtmlHead -Title 'SPSTrust - Trust Matrix Report'))

    $encApp = ConvertTo-SPSHtmlEncoded -Value "$($Status.Application)"
    $encEnv = ConvertTo-SPSHtmlEncoded -Value "$($Status.Environment)"
    $encDomain = ConvertTo-SPSHtmlEncoded -Value "$($Status.Domain)"
    $encGen = ConvertTo-SPSHtmlEncoded -Value "$($Status.GeneratedAtUtc)"
    $encVersion = ConvertTo-SPSHtmlEncoded -Value "$($Status.Version)"

    [void]$sb.Append("<h1>SPSTrust - Trust Matrix Report</h1>")
    [void]$sb.Append("<div class=`"meta`">Application: <strong>$encApp</strong> &middot; Environment: <strong>$encEnv</strong> &middot; Domain: <strong>$encDomain</strong> &middot; Generated: <strong>$encGen</strong> (UTC) &middot; Version: <strong>$encVersion</strong></div>")

    # Summary cards.
    [void]$sb.Append("<div class=`"summary`"><div class=`"cards`">")
    [void]$sb.Append((Get-SPSReportCardHtml -Value $rows.Count -Label 'Relationships' -Sub 'farm / farm / service' -Tone 'accent'))
    [void]$sb.Append((Get-SPSReportCardHtml -Value $presentCount -Label 'Present' -Tone 'clean'))
    [void]$sb.Append((Get-SPSReportCardHtml -Value $absentCount -Label 'Absent' -Tone $(if ($absentCount -gt 0) { 'alert' } else { '' })))
    [void]$sb.Append((Get-SPSReportCardHtml -Value $naCount -Label 'N/A'))
    if ($errorCount -gt 0) {
        [void]$sb.Append((Get-SPSReportCardHtml -Value $errorCount -Label 'Errors' -Tone 'alert'))
    }
    [void]$sb.Append("</div></div>")

    # Controls.
    [void]$sb.Append("<div class=`"controls`"><input id=`"matrix-search`" class=`"search`" type=`"text`" placeholder=`"Filter rows...`"><span id=`"matrix-info`" class=`"info`"></span></div>")

    if ($rows.Count -eq 0) {
        [void]$sb.Append("<p class=`"empty`">No trust relationships are declared in the configuration.</p>")
    }
    else {
        [void]$sb.Append("<table id=`"trust-matrix`"><thead><tr>")
        foreach ($col in @('Publishing Farm', 'Consuming Farm', 'Service')) {
            [void]$sb.Append("<th>$col</th>")
        }
        foreach ($dim in $dimensions) {
            [void]$sb.Append("<th>$($dim.Label)</th>")
        }
        [void]$sb.Append("<th>Notes</th></tr></thead><tbody>")

        foreach ($row in $rows) {
            [void]$sb.Append("<tr>")
            [void]$sb.Append("<td>$(ConvertTo-SPSHtmlEncoded -Value "$($row.PublishingFarm)")</td>")
            [void]$sb.Append("<td>$(ConvertTo-SPSHtmlEncoded -Value "$($row.ConsumingFarm)")</td>")
            [void]$sb.Append("<td>$(ConvertTo-SPSHtmlEncoded -Value "$($row.Service)")</td>")
            foreach ($dim in $dimensions) {
                [void]$sb.Append("<td>$(Get-Pill -Value "$($row.$($dim.Field))")</td>")
            }
            [void]$sb.Append("<td>$(ConvertTo-SPSHtmlEncoded -Value "$($row.Notes)")</td>")
            [void]$sb.Append("</tr>")
        }

        [void]$sb.Append("</tbody></table>")
    }

    [void]$sb.Append("<div class=`"footer`">Generated by SPSTrust &middot; <a href=`"https://github.com/luigilink/SPSTrust`">github.com/luigilink/SPSTrust</a></div>")
    [void]$sb.Append((Get-SPSReportHtmlScript))
    [void]$sb.Append("</body></html>")

    $outDir = Split-Path -Path $OutputPath -Parent
    if ($outDir -and -not (Test-Path -Path $outDir)) {
        $null = New-Item -Path $outDir -ItemType Directory -Force
    }

    Set-Content -Path $OutputPath -Value $sb.ToString() -Encoding UTF8
    Write-Verbose -Message "Export-SPSTrustReport: wrote report to '$OutputPath'."

    return $OutputPath
}
