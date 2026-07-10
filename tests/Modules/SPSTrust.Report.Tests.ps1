# Pester tests for the SPSTrust.Common reporting/audit functions (2.1.0):
# Get-SPSTrustStatus, Export-SPSTrustReport, Backup-SPSJsonFile and the private
# HTML report helpers.

BeforeAll {
    $repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:moduleRoot = Join-Path -Path $repoRoot -ChildPath 'src/Modules/SPSTrust.Common'
    $script:moduleManifest = Join-Path -Path $script:moduleRoot -ChildPath 'SPSTrust.Common.psd1'
    $script:moduleName = 'SPSTrust.Common'

    # Stub SharePoint cmdlets so the module imports on non-Windows hosts.
    $spsStubs = @(
        'Get-SPServer', 'Get-SPFarm', 'Get-SPServiceApplication', 'Get-SPTrustedRootAuthority',
        'Get-SPTrustedServiceTokenIssuer', 'Add-PSSnapin', 'Get-PSSnapin', 'New-PSSession',
        'Remove-PSSession', 'Invoke-Command'
    )
    foreach ($name in $spsStubs) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $sb = [ScriptBlock]::Create("function global:$name { param() }")
            & $sb
        }
    }

    Import-Module -Name $script:moduleManifest -Force -DisableNameChecking

    $script:sampleFarms = @(
        [pscustomobject]@{ Name = 'SEARCH'; Server = 'srvsearch' }
        [pscustomobject]@{ Name = 'SERVICES'; Server = 'srvservices' }
        [pscustomobject]@{ Name = 'CONTENT'; Server = 'srvcontent' }
    )
    $script:sampleTrusts = @(
        [pscustomobject]@{ LocalFarm = 'SERVICES'; RemoteFarms = @('CONTENT'); Services = @('CONTOSOPRODUPS') }
        [pscustomobject]@{ LocalFarm = 'CONTENT'; RemoteFarms = @('SEARCH'); Services = @('Content') }
    )
    $securePwd = ConvertTo-SecureString 'p@ssw0rd!' -AsPlainText -Force
    $script:sampleCred = [System.Management.Automation.PSCredential]::new('CONTOSO\svc', $securePwd)
}

AfterAll {
    Remove-Module -Name 'SPSTrust.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SPSTrust.Common reporting public surface' {

    It 'exports <_>' -ForEach @('Backup-SPSJsonFile', 'Get-SPSTrustStatus', 'Export-SPSTrustReport') {
        Get-Command -Name $_ -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'keeps the HTML helper <_> private (module scope only)' -ForEach @(
        'ConvertTo-SPSHtmlEncoded', 'Get-SPSReportHtmlHead', 'Get-SPSReportCardHtml', 'Get-SPSReportHtmlScript') {
        (Get-Module -Name $script:moduleName).ExportedFunctions.Keys | Should -Not -Contain $_
        $helper = $_
        InModuleScope -ModuleName 'SPSTrust.Common' -Parameters @{ helper = $helper } {
            param($helper)
            Get-Command -Name $helper -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'ConvertTo-SPSHtmlEncoded' {
    It 'escapes HTML metacharacters' {
        InModuleScope -ModuleName 'SPSTrust.Common' {
            ConvertTo-SPSHtmlEncoded -Value 'a<b>&"x''y' | Should -Be 'a&lt;b&gt;&amp;&quot;x&#39;y'
        }
    }
    It 'returns empty string for null/empty input' {
        InModuleScope -ModuleName 'SPSTrust.Common' {
            ConvertTo-SPSHtmlEncoded -Value '' | Should -Be ''
        }
    }
}

Describe 'Get-SPSTrustStatus' {

    BeforeEach {
        # Default: everything Present. Individual tests override specific getters.
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSFarmId -MockWith { @{ Value = [guid]::NewGuid() } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSTrustedRootAuthority -MockWith { @{ Ensure = 'Present' } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSTrustedServiceTokenIssuer -MockWith { @{ Ensure = 'Present' } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSPublishedServiceApplication -MockWith { @{ Ensure = 'Present'; Uri = 'urn:x'; Type = 'T' } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSTopologyServiceAppPermission -MockWith { @{ Ensure = 'Present' } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSPublishedServiceAppPermission -MockWith { @{ Ensure = 'Present' } }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSPublishedServiceAppProxy -MockWith { @{ Ensure = 'Present' } }
    }

    It 'produces one row per publishing/consuming/service combination' {
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        $status.RowCount | Should -Be 2
        @($status.Rows).Count | Should -Be 2
    }

    It 'carries metadata through' {
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred `
            -Application 'contoso' -Environment 'PROD' -Version '2.1.0'
        $status.Application | Should -Be 'contoso'
        $status.Environment | Should -Be 'PROD'
        $status.Domain | Should -Be 'contoso.com'
        $status.Version | Should -Be '2.1.0'
        $status.GeneratedAtUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    }

    It 'resolves target server FQDNs from the farm inventory' {
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        $svcRow = $status.Rows | Where-Object { $_.PublishingFarm -eq 'SERVICES' }
        $svcRow.PublishingServer | Should -Be 'srvservices.contoso.com'
        $svcRow.ConsumingServer | Should -Be 'srvcontent.contoso.com'
    }

    It 'marks STS/Published/SA-Permission/Proxy as N/A for a Content service' {
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        $contentRow = $status.Rows | Where-Object { $_.Service -eq 'Content' }
        $contentRow.StsTrust | Should -Be 'N/A'
        $contentRow.Published | Should -Be 'N/A'
        $contentRow.ServiceAppPermission | Should -Be 'N/A'
        $contentRow.Proxy | Should -Be 'N/A'
        # ROOT and Topology still apply to a content farm.
        $contentRow.RootTrust | Should -Be 'Present'
        $contentRow.TopologyPermission | Should -Be 'Present'
    }

    It 'reflects an Absent dimension' {
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSPublishedServiceAppProxy -MockWith { @{ Ensure = 'Absent' } }
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        $svcRow = $status.Rows | Where-Object { $_.Service -eq 'CONTOSOPRODUPS' }
        $svcRow.Proxy | Should -Be 'Absent'
    }

    It 'captures Error and a Note when a getter throws (does not abort)' {
        Mock -ModuleName 'SPSTrust.Common' -CommandName Get-SPSTrustedRootAuthority -MockWith { throw 'boom' }
        $status = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        $status.RowCount | Should -Be 2
        $svcRow = $status.Rows | Where-Object { $_.Service -eq 'CONTOSOPRODUPS' }
        $svcRow.RootTrust | Should -Be 'Error'
        $svcRow.Notes | Should -Match 'ROOT: boom'
    }

    It 'never calls a state-changing function' {
        Mock -ModuleName 'SPSTrust.Common' -CommandName Set-SPSTrustedRootAuthority -MockWith { }
        Mock -ModuleName 'SPSTrust.Common' -CommandName Publish-SPSServiceApplication -MockWith { }
        Mock -ModuleName 'SPSTrust.Common' -CommandName New-SPSPublishedServiceAppProxy -MockWith { }
        $null = Get-SPSTrustStatus -Farms $script:sampleFarms -Trusts $script:sampleTrusts `
            -Domain 'contoso.com' -InstallAccount $script:sampleCred
        Should -Invoke -ModuleName 'SPSTrust.Common' -CommandName Set-SPSTrustedRootAuthority -Times 0
        Should -Invoke -ModuleName 'SPSTrust.Common' -CommandName Publish-SPSServiceApplication -Times 0
        Should -Invoke -ModuleName 'SPSTrust.Common' -CommandName New-SPSPublishedServiceAppProxy -Times 0
    }
}

Describe 'Export-SPSTrustReport' {

    BeforeEach {
        $script:tempRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:tempRoot -ItemType Directory -Force
        $script:status = [ordered]@{
            Application    = 'contoso'
            Environment    = 'PROD'
            Domain         = 'contoso.com'
            Version        = '2.1.0'
            GeneratedAtUtc = '2026-07-10T12:00:00Z'
            RowCount       = 2
            Rows           = @(
                [ordered]@{ PublishingFarm = 'SERVICES'; PublishingServer = 'srvservices.contoso.com'; ConsumingFarm = 'CONTENT'; ConsumingServer = 'srvcontent.contoso.com'; Service = 'CONTOSOPRODUPS'; RootTrust = 'Present'; StsTrust = 'Present'; Published = 'Present'; TopologyPermission = 'Present'; ServiceAppPermission = 'Absent'; Proxy = 'Absent'; Notes = '' }
                [ordered]@{ PublishingFarm = 'CONTENT'; PublishingServer = 'srvcontent.contoso.com'; ConsumingFarm = 'SEARCH'; ConsumingServer = 'srvsearch.contoso.com'; Service = 'Content'; RootTrust = 'Present'; StsTrust = 'N/A'; Published = 'N/A'; TopologyPermission = 'Present'; ServiceAppPermission = 'N/A'; Proxy = 'N/A'; Notes = '' }
            )
        }
    }

    It 'writes an HTML file and returns its path' {
        $out = Join-Path -Path $script:tempRoot -ChildPath 'report.html'
        $result = Export-SPSTrustReport -Status $script:status -OutputPath $out
        $result | Should -Be $out
        $out | Should -Exist
    }

    It 'renders the interactive matrix table with status pills' {
        $out = Join-Path -Path $script:tempRoot -ChildPath 'report.html'
        Export-SPSTrustReport -Status $script:status -OutputPath $out | Out-Null
        $html = Get-Content -Path $out -Raw
        $html | Should -Match 'id="trust-matrix"'
        $html | Should -Match 'pill-present'
        $html | Should -Match 'pill-absent'
        $html | Should -Match 'pill-na'
        $html | Should -Match '<script>'
    }

    It 'creates the output directory if missing' {
        $out = Join-Path -Path $script:tempRoot -ChildPath 'nested/deep/report.html'
        Export-SPSTrustReport -Status $script:status -OutputPath $out | Out-Null
        $out | Should -Exist
    }

    It 'round-trips through a results JSON file (-InputFile)' {
        $jsonPath = Join-Path -Path $script:tempRoot -ChildPath 'results.json'
        $script:status | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
        $out = Join-Path -Path $script:tempRoot -ChildPath 'from-json.html'
        Export-SPSTrustReport -InputFile $jsonPath -OutputPath $out | Out-Null
        $out | Should -Exist
        (Get-Content -Path $out -Raw) | Should -Match 'id="trust-matrix"'
    }

    It 'throws when -InputFile does not exist' {
        $out = Join-Path -Path $script:tempRoot -ChildPath 'x.html'
        { Export-SPSTrustReport -InputFile (Join-Path $script:tempRoot 'missing.json') -OutputPath $out } |
            Should -Throw
    }

    It 'HTML-encodes values to guard against injection' {
        $script:status.Rows[0].Service = '<script>alert(1)</script>'
        $out = Join-Path -Path $script:tempRoot -ChildPath 'enc.html'
        Export-SPSTrustReport -Status $script:status -OutputPath $out | Out-Null
        $html = Get-Content -Path $out -Raw
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }
}

Describe 'Backup-SPSJsonFile' {

    BeforeEach {
        $script:tempRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:tempRoot -ItemType Directory -Force
        $script:jsonPath = Join-Path -Path $script:tempRoot -ChildPath 'CONTOSO-PROD.json'
        $script:historyFolder = Join-Path -Path $script:tempRoot -ChildPath 'history'
    }

    It 'returns $null and creates nothing when the source does not exist' {
        $result = Backup-SPSJsonFile -Path $script:jsonPath -HistoryFolder $script:historyFolder
        $result | Should -BeNullOrEmpty
        $script:historyFolder | Should -Not -Exist
    }

    It 'archives the existing file with a timestamped name and leaves the original' {
        Set-Content -Path $script:jsonPath -Value '{"a":1}'
        $result = Backup-SPSJsonFile -Path $script:jsonPath -HistoryFolder $script:historyFolder -TimeStamp '20260710-1200'
        $result | Should -Exist
        (Split-Path -Path $result -Leaf) | Should -Be 'CONTOSO-PROD-20260710-1200.json'
        $script:jsonPath | Should -Exist
    }
}
