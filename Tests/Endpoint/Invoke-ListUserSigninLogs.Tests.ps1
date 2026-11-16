# Pester tests for Invoke-ListUserSigninLogs.
# The endpoint used to send an unbounded beta signIns query that Graph could not answer inside its
# 100 s limit (Accelera, Suntec incident 2026-11-11). These pin the bounded v1.0 shape.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-ListUserSigninLogs.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-ListUserSigninLogs.ps1 under Modules/' }

    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) { $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode]) }

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
    function New-GraphGetRequest { param($uri, $tenantid, $noPagination) }

    . $FunctionPath

    function New-SigninRequest {
        param([hashtable]$Query = @{})
        $Merged = @{ tenantFilter = 'contoso.onmicrosoft.com'; UserID = '1366d094-251d-4108-a3b1-20b18c223b8b' }
        foreach ($Key in $Query.Keys) { $Merged[$Key] = $Query[$Key] }
        [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ListUserSigninLogs' }; Headers = @{}; Query = [pscustomobject]$Merged }
    }
}

Describe 'Invoke-ListUserSigninLogs' {
    BeforeEach {
        $script:Uri = $null
        Mock -CommandName New-GraphGetRequest -MockWith { param($uri) $script:Uri = $uri; @([pscustomobject]@{ id = 'row1' }) }
    }

    It 'uses v1.0, never beta' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest) | Out-Null
        $script:Uri | Should -Match '^https://graph\.microsoft\.com/v1\.0/auditLogs/signIns\?'
        $script:Uri | Should -Not -Match '/beta/'
    }

    It 'always bounds the query with createdDateTime ge and le' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest) | Out-Null
        $script:Uri | Should -Match "userId eq '1366d094-251d-4108-a3b1-20b18c223b8b' and createdDateTime ge \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ and createdDateTime le \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
    }

    It 'honours an explicit window' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-10T00:00:00Z'; endDate = '2026-11-12T23:59:59Z' }) | Out-Null
        $script:Uri | Should -Match 'createdDateTime ge 2026-11-10T00:00:00Z and createdDateTime le 2026-11-12T23:59:59Z'
    }

    It 'clamps a window wider than 72 hours to the most recent 72' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-10-01T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' }) | Out-Null
        $script:Uri | Should -Match 'createdDateTime ge 2026-11-09T00:00:00Z and createdDateTime le 2026-11-12T00:00:00Z'
    }

    It 'caps top at 999 and defaults to 50' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ top = '5000' }) | Out-Null
        $script:Uri | Should -Match '\$top=999'
        Invoke-ListUserSigninLogs -Request (New-SigninRequest) | Out-Null
        $script:Uri | Should -Match '\$top=50&'
    }

    It 'accepts a UPN and filters on userPrincipalName' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ UserID = 'ejuarez@suntecconcrete.com' }) | Out-Null
        $script:Uri | Should -Match "userPrincipalName eq 'ejuarez@suntecconcrete.com'"
    }

    It 'refuses a UserID that would inject into the filter, without calling Graph' {
        $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ UserID = "x') or (true" })
        $Response.StatusCode | Should -Be 500
        Should -Invoke -CommandName New-GraphGetRequest -Times 0 -Exactly
    }

    It 'returns 500 with the Graph error when the read fails' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'The request timed out after 100s.' }
        $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest)
        $Response.StatusCode | Should -Be 500
        "$($Response.Body)" | Should -Match 'timed out'
    }
}
