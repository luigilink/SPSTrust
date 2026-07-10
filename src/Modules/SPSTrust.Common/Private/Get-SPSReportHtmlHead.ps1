function Get-SPSReportHtmlHead {
    <#
        .SYNOPSIS
        Returns the document head (with the embedded stylesheet) and the opening body tag.

        .DESCRIPTION
        Emits a self-contained <head> block (no CDN, works offline on a SharePoint
        server) with the embedded SPSTrust report stylesheet, followed by the opening
        <body> tag. The stylesheet includes the status "pill" styles used to render the
        trust matrix (present / absent / n-a).

        .PARAMETER Title
        Page title used in the <title> element.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Title
    )

    $css = @'
:root{--brand:#1f6fb2;--brand-dark:#155a91;--ink:#222;--muted:#666;--line:#e3e3e3;--zebra:#f7f9fb;--ok:#2e9b57;--warn:#c19c00;--alert:#c0392b}
*{box-sizing:border-box}
body{font-family:'Aptos','Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;color:var(--ink);margin:0;padding:24px;background:#fff}
h1{color:var(--brand);font-size:22px;margin:0 0 4px}
h2{color:var(--brand);font-size:16px;margin:24px 0 8px;border-bottom:2px solid var(--brand);padding-bottom:4px}
h3{color:var(--brand-dark);font-size:13px;margin:0 0 6px}
.meta{color:var(--muted);font-size:12px;margin-bottom:16px}
.summary{background:#eef5fb;border:1px solid #cfe0ef;border-left:4px solid var(--brand);border-radius:6px;padding:16px;margin-bottom:8px}
.cards{display:flex;flex-wrap:wrap;gap:12px}
.card{background:#fff;border:1px solid var(--line);border-radius:6px;padding:12px 16px;min-width:120px}
.card-value{font-size:24px;font-weight:700;color:var(--brand)}
.card-label{font-size:12px;color:var(--muted)}
.card-sub{font-size:11px;color:var(--muted);margin-top:2px}
.card.accent{background:#eef5fb;border-color:#cfe0ef}
.card.clean .card-value{color:var(--ok)}
.card.alert .card-value{color:var(--alert)}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{background:var(--brand);color:#fff;cursor:pointer;user-select:none;position:sticky;top:0}
td.num,th.num{text-align:right}
tbody tr:nth-child(even){background:var(--zebra)}
.controls{display:flex;justify-content:space-between;align-items:center;margin:12px 0;flex-wrap:wrap;gap:8px}
.search{padding:6px 10px;border:1px solid var(--line);border-radius:4px;font-size:13px;width:280px;max-width:100%}
.info{color:var(--muted);font-size:12px}
.pill{display:inline-block;min-width:64px;text-align:center;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;line-height:1.4}
.pill-present{background:#e6f4ec;color:var(--ok);border:1px solid #bfe2cd}
.pill-absent{background:#fbeceb;color:var(--alert);border:1px solid #f0c9c5}
.pill-na{background:#f0f0f0;color:var(--muted);border:1px solid #e0e0e0}
.empty{color:var(--ok);font-size:13px;margin:8px 0 20px;font-weight:600}
.footer{color:var(--muted);font-size:11px;margin-top:24px;border-top:1px solid var(--line);padding-top:8px}
'@

    return "<!DOCTYPE html><html lang=`"en`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width, initial-scale=1`"><title>$Title</title><style>$css</style></head><body>"
}
