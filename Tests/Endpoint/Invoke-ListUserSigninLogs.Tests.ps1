# Pester tests for Invoke-ListUserSigninLogs.
# The endpoint used to send an unbounded beta signIns query that Graph could not answer inside its
# 100 s limit. These pin the bounded v1.0 shape and the <=6 h slicing of wider windows.

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
    function New-GraphBulkRequest { param($Requests, $tenantid, $NoPaginateIds, $Version) }

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
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '2' }) | Out-Null
        $script:Uri | Should -Match '^https://graph\.microsoft\.com/v1\.0/auditLogs/signIns\?'
        $script:Uri | Should -Not -Match '/beta/'
    }

    It 'always bounds the query with createdDateTime ge and le' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '2' }) | Out-Null
        $script:Uri | Should -Match "userId eq '1366d094-251d-4108-a3b1-20b18c223b8b' and createdDateTime ge \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ and createdDateTime le \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
    }

    It 'honours an explicit window' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-12T00:00:00Z'; endDate = '2026-11-12T03:59:59Z' }) | Out-Null
        $script:Uri | Should -Match 'createdDateTime ge 2026-11-12T00:00:00Z and createdDateTime le 2026-11-12T03:59:59Z'
    }

    It 'clamps a window wider than 72 hours to the most recent 72' {
        Mock -CommandName New-GraphBulkRequest -MockWith { $script:Reqs = @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } }); @() }
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-10-01T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' }) | Out-Null
        $script:Reqs[0].url | Should -Match 'createdDateTime ge 2026-11-09T00:00:00Z and'
        $script:Reqs[-1].url | Should -Match 'createdDateTime le 2026-11-12T00:00:00Z'
    }

    It 'caps top at 999 and defaults to 50' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ top = '5000'; hours = '2' }) | Out-Null
        $script:Uri | Should -Match '\$top=999'
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '2' }) | Out-Null
        $script:Uri | Should -Match '\$top=50&'
    }

    It 'accepts a UPN and filters on userPrincipalName' {
        Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ UserID = 'user@contoso.com'; hours = '2' }) | Out-Null
        $script:Uri | Should -Match "userPrincipalName eq 'user@contoso.com'"
    }

    It 'refuses a UserID that would inject into the filter, without calling Graph' {
        $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ UserID = "x') or (true" })
        $Response.StatusCode | Should -Be 500
        Should -Invoke -CommandName New-GraphGetRequest -Times 0 -Exactly
    }

    It 'returns 500 with the Graph error when the read fails' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'The request timed out after 100s.' }
        $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '2' })
        $Response.StatusCode | Should -Be 500
        "$($Response.Body)" | Should -Match 'timed out'
    }

    Context 'slicing windows wider than 6 hours' {
        BeforeEach {
            $script:Reqs = $null
            $script:BulkCalls = 0
            # Answer every slice with one row whose id is unique to the slice, timestamped at the slice start.
            Mock -CommandName New-GraphBulkRequest -MockWith {
                $script:BulkCalls++
                $script:Reqs = @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } })
                foreach ($R in @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } })) {
                    $From = [regex]::Match($R.url, 'createdDateTime ge (\S+)').Groups[1].Value
                    [pscustomobject]@{ id = $R.id; status = 200; body = [pscustomobject]@{ value = @([pscustomobject]@{ id = "row-$($R.id)"; createdDateTime = $From }) } }
                }
            }
        }

        It 'sends a 2h window as a single plain request, not a batch' {
            Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-12T00:00:00Z'; endDate = '2026-11-12T02:00:00Z' }) | Out-Null
            $script:BulkCalls | Should -Be 0
            Should -Invoke -CommandName New-GraphGetRequest -Times 1 -Exactly
        }

        It 'splits 24h into 4 slices of 6h with contiguous boundaries' {
            Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-11T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' }) | Out-Null
            $script:Reqs.Count | Should -Be 4
            $script:Reqs[0].url | Should -Match 'ge 2026-11-11T00:00:00Z and createdDateTime lt 2026-11-11T06:00:00Z'
            $script:Reqs[1].url | Should -Match 'ge 2026-11-11T06:00:00Z and createdDateTime lt 2026-11-11T12:00:00Z'
            $script:Reqs[2].url | Should -Match 'ge 2026-11-11T12:00:00Z and createdDateTime lt 2026-11-11T18:00:00Z'
            $script:Reqs[3].url | Should -Match 'ge 2026-11-11T18:00:00Z and createdDateTime le 2026-11-12T00:00:00Z'
            foreach ($R in $script:Reqs) { $R.rawUrl | Should -Not -Match ' ' }
        }

        It 'splits 72h into 12 slices, each at most 6h, covering the window exactly' {
            Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-09T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' }) | Out-Null
            $script:Reqs.Count | Should -Be 12
            $script:Reqs[0].url | Should -Match 'ge 2026-11-09T00:00:00Z'
            $script:Reqs[11].url | Should -Match 'le 2026-11-12T00:00:00Z'
            foreach ($R in $script:Reqs) {
                $M = [regex]::Match($R.url, 'ge (\d{4}-[\d:T-]+Z) and createdDateTime (?:lt|le) (\d{4}-[\d:T-]+Z)')
                (([datetime]$M.Groups[2].Value) - ([datetime]$M.Groups[1].Value)).TotalHours | Should -BeLessOrEqual 6
                $R.url | Should -Match "userId eq '1366d094-251d-4108-a3b1-20b18c223b8b'"
                $R.url | Should -Match '\$top=50'
            }
        }

        It 'uses the v1.0 bulk path and never paginates a slice' {
            Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '24' }) | Out-Null
            Should -Invoke -CommandName New-GraphBulkRequest -Times 1 -Exactly -ParameterFilter { $Version -eq 'v1.0' -and @($NoPaginateIds).Count -eq 4 }
        }

        It 'merges, sorts newest first and returns a bare array when every slice succeeds' {
            $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-11T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' })
            $Response.StatusCode | Should -Be 200
            @($Response.Body).Count | Should -Be 4
            $Response.Body[0].id | Should -Be 'row-slice3'
            $Response.Body[3].id | Should -Be 'row-slice0'
        }

        It 'dedupes rows that appear in more than one slice and applies top to the merged set' {
            Mock -CommandName New-GraphBulkRequest -MockWith {
                foreach ($R in @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } })) {
                    $Rows = @([pscustomobject]@{ id = 'dup'; createdDateTime = '2026-11-11T05:59:59Z' }, [pscustomobject]@{ id = "u-$($R.id)"; createdDateTime = '2026-11-11T0' + $R.id.Substring(5) + ':00:00Z' })
                    [pscustomobject]@{ id = $R.id; status = 200; body = [pscustomobject]@{ value = $Rows } }
                }
            }
            $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-11T00:00:00Z'; endDate = '2026-11-12T00:00:00Z'; top = '3' })
            @($Response.Body | Where-Object id -eq 'dup').Count | Should -Be 1
            @($Response.Body).Count | Should -Be 3
        }

        It 'returns 200 with partial metadata naming the failed slice, keeping the other slices' {
            Mock -CommandName New-GraphBulkRequest -MockWith {
                foreach ($R in @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } })) {
                    if ($R.id -eq 'slice1') {
                        [pscustomobject]@{ id = $R.id; status = 504; body = [pscustomobject]@{ error = [pscustomobject]@{ message = 'gateway timeout' } } }
                    } else {
                        [pscustomobject]@{ id = $R.id; status = 200; body = [pscustomobject]@{ value = @([pscustomobject]@{ id = "row-$($R.id)"; createdDateTime = '2026-11-11T00:00:00Z' }) } }
                    }
                }
            }
            $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-11T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' })
            $Response.StatusCode | Should -Be 200
            @($Response.Body.Results).Count | Should -Be 3
            $Response.Body.Metadata.partial | Should -BeTrue
            @($Response.Body.Metadata.failedSlices).Count | Should -Be 1
            $Response.Body.Metadata.failedSlices[0].from | Should -Be '2026-11-11T06:00:00Z'
            $Response.Body.Metadata.failedSlices[0].to | Should -Be '2026-11-11T12:00:00Z'
            $Response.Body.Metadata.failedSlices[0].reason | Should -Match 'gateway timeout'
        }

        It 'treats a slice missing from the batch reply as failed' {
            Mock -CommandName New-GraphBulkRequest -MockWith {
                [pscustomobject]@{ id = 'slice0'; status = 200; body = [pscustomobject]@{ value = @([pscustomobject]@{ id = 'a'; createdDateTime = '2026-11-11T00:00:00Z' }) } }
            }
            $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ startDate = '2026-11-11T00:00:00Z'; endDate = '2026-11-12T00:00:00Z' })
            $Response.StatusCode | Should -Be 200
            @($Response.Body.Metadata.failedSlices).Count | Should -Be 3
        }

        It 'returns 500 when every slice fails' {
            Mock -CommandName New-GraphBulkRequest -MockWith {
                foreach ($R in @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; method = $_.method; url = [uri]::UnescapeDataString($_.url); rawUrl = $_.url } })) { [pscustomobject]@{ id = $R.id; status = 500; body = [pscustomobject]@{ error = [pscustomobject]@{ message = 'boom' } } } }
            }
            $Response = Invoke-ListUserSigninLogs -Request (New-SigninRequest -Query @{ hours = '24' })
            $Response.StatusCode | Should -Be 500
            "$($Response.Body)" | Should -Match 'boom'
        }
    }
}
