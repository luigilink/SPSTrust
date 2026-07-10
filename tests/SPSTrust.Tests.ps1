# Pester tests for SPSTrust.ps1
# Resolve repo root - works on CI/CD (GitHub Actions) and local runs

BeforeAll {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:scriptPath = Join-Path -Path $repoRoot -ChildPath 'src/SPSTrust.ps1'
    $script:scriptContent = Get-Content -Path $script:scriptPath -Raw -ErrorAction SilentlyContinue
    $script:configExample = Join-Path -Path $repoRoot -ChildPath 'src/Config/CONTOSO-PROD.example.psd1'
}

Describe 'SPSTrust.ps1 File Existence' {

    It 'SPSTrust.ps1 exists' {
        $script:scriptPath | Should -Exist
    }

    It 'is a PowerShell script file' {
        (Get-Item $script:scriptPath).Extension | Should -Be '.ps1'
    }

    It 'has valid PowerShell syntax' {
        $parseErrors = $null
        $tokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput(
            $script:scriptContent, [ref]$tokens, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty
    }
}

Describe 'SPSTrust.ps1 Metadata' {

    It 'Should contain a SYNOPSIS' {
        $script:scriptContent | Should -Match '\.SYNOPSIS'
    }

    It 'Should contain a DESCRIPTION' {
        $script:scriptContent | Should -Match '\.DESCRIPTION'
    }

    It 'Should contain an EXAMPLE' {
        $script:scriptContent | Should -Match '\.EXAMPLE'
    }

    It 'Should declare an Author in NOTES' {
        $script:scriptContent | Should -Match 'Author:\s*luigilink'
    }

    It 'Should source its Version from the SPSTrust.Common manifest' {
        $script:scriptContent | Should -Match 'Version:\s*Defined by the SPSTrust\.Common module manifest'
    }

    It 'Should require PowerShell 5.1 or higher' {
        $script:scriptContent | Should -Match '#requires\s+-Version\s+5\.1'
    }

    It 'Should read its version from Get-Module at runtime' {
        $script:scriptContent | Should -Match "Get-Module -Name 'SPSTrust\.Common'"
    }

    It 'Should import the SPSTrust.Common manifest' {
        $script:scriptContent | Should -Match 'SPSTrust\.Common\\SPSTrust\.Common\.psd1'
    }

    It 'Should load config via Import-PowerShellDataFile' {
        $script:scriptContent | Should -Match 'Import-PowerShellDataFile'
    }
}

Describe 'SPSTrust.ps1 Parameters' {

    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $script:scriptContent, [ref]$null, [ref]$null)
        $script:paramBlock = $ast.ParamBlock
    }

    It 'Should define a param block' {
        $script:paramBlock | Should -Not -BeNullOrEmpty
    }

    It 'Should expose a mandatory ConfigFile parameter' {
        $configParam = $script:paramBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'ConfigFile'
        }
        $configParam | Should -Not -BeNullOrEmpty

        $paramAttr = $configParam.Attributes | Where-Object {
            $_ -is [System.Management.Automation.Language.AttributeAst] -and
            $_.TypeName.Name -eq 'Parameter'
        }
        $mandatoryArg = $paramAttr.NamedArguments |
            Where-Object { $_.ArgumentName -eq 'Mandatory' }
        $mandatoryArg | Should -Not -BeNullOrEmpty
    }

    It 'ConfigFile should validate a .psd1 path' {
        $script:scriptContent | Should -Match "\`$_ -like '\*\.psd1'"
    }

    It 'Should expose a mandatory FarmAccount parameter' {
        $farmParam = $script:paramBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'FarmAccount'
        }
        $farmParam | Should -Not -BeNullOrEmpty
    }

    It 'Should expose a CleanServices switch' {
        $cleanParam = $script:paramBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'CleanServices'
        }
        $cleanParam | Should -Not -BeNullOrEmpty
        $cleanParam.StaticType.Name | Should -Be 'SwitchParameter'
    }

    It 'Should expose a LogRetentionDays parameter' {
        $logParam = $script:paramBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'LogRetentionDays'
        }
        $logParam | Should -Not -BeNullOrEmpty
    }
}

Describe 'SPSTrust example configuration' {

    It 'example config file exists' {
        $script:configExample | Should -Exist
    }

    It 'is a valid PowerShell data file' {
        { Import-PowerShellDataFile -Path $script:configExample } | Should -Not -Throw
    }

    It 'declares the required top-level keys' {
        $cfg = Import-PowerShellDataFile -Path $script:configExample
        foreach ($key in @('ConfigurationName', 'ApplicationName', 'Domain', 'CertFileShared', 'Trusts', 'Farms')) {
            $cfg.ContainsKey($key) | Should -BeTrue
        }
    }

    It 'every Trust references farms that exist in the Farms inventory' {
        $cfg = Import-PowerShellDataFile -Path $script:configExample
        $farmNames = $cfg.Farms.Name
        foreach ($trust in $cfg.Trusts) {
            $trust.LocalFarm | Should -BeIn $farmNames
            foreach ($remote in $trust.RemoteFarms) {
                $remote | Should -BeIn $farmNames
            }
        }
    }

    It 'every Farm entry has a Name and a Server' {
        $cfg = Import-PowerShellDataFile -Path $script:configExample
        foreach ($farm in $cfg.Farms) {
            $farm.Name | Should -Not -BeNullOrEmpty
            $farm.Server | Should -Not -BeNullOrEmpty
        }
    }
}
