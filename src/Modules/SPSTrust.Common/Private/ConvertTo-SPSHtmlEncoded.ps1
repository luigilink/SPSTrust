function ConvertTo-SPSHtmlEncoded {
    <#
        .SYNOPSIS
        HTML-encodes a string for safe insertion into generated HTML reports.

        .DESCRIPTION
        Replaces the five characters that are significant in HTML markup
        (& < > " ') with their entity equivalents. Used by
        Export-SPSTrustReport to neutralize values (database names,
        site/web IDs, logins, messages) before baking them into the report.

        Returns an empty string for null or empty input.

        .PARAMETER Value
        The string to encode.

        .EXAMPLE
        ConvertTo-SPSHtmlEncoded -Value 'SERVICES <prod> & "co"'
        # SERVICES &lt;prod&gt; &amp; &quot;co&quot;
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [System.String]
        $Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return ''
        }

        $sb = [System.Text.StringBuilder]::new()
        foreach ($char in $Value.ToCharArray()) {
            switch ($char) {
                '&' { [void]$sb.Append('&amp;') }
                '<' { [void]$sb.Append('&lt;') }
                '>' { [void]$sb.Append('&gt;') }
                '"' { [void]$sb.Append('&quot;') }
                "'" { [void]$sb.Append('&#39;') }
                default { [void]$sb.Append($char) }
            }
        }
        return $sb.ToString()
    }
}
