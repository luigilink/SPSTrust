function Get-SPSReportCardHtml {
    <#
        .SYNOPSIS
        Builds the HTML for one summary "card" (a big number plus a label).

        .PARAMETER Value
        The value shown as the big number.

        .PARAMETER Label
        The label shown under the value.

        .PARAMETER Sub
        Optional sub-label shown under the label.

        .PARAMETER Tone
        Optional visual tone: '', 'accent', 'clean' (green) or 'alert' (red).
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Label,

        [Parameter()]
        [System.String]
        $Sub = '',

        [Parameter()]
        [ValidateSet('', 'accent', 'clean', 'alert')]
        [System.String]
        $Tone = ''
    )

    $encValue = ConvertTo-SPSHtmlEncoded -Value ("$Value")
    $encLabel = ConvertTo-SPSHtmlEncoded -Value $Label
    $encSub = ConvertTo-SPSHtmlEncoded -Value $Sub
    $toneClass = if ([string]::IsNullOrEmpty($Tone)) { '' } else { " $Tone" }
    $subHtml = if ([string]::IsNullOrEmpty($encSub)) { '' } else { "<div class=`"card-sub`">$encSub</div>" }
    return "<div class=`"card$toneClass`"><div class=`"card-value`">$encValue</div><div class=`"card-label`">$encLabel</div>$subHtml</div>"
}
