# Pester tests for Invoke-ListSharepointSettings.
# The endpoint must use application authentication because it runs without a delegated user.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-ListSharepointSettings.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-ListSharepointSettings.ps1 under Modules/' }

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function New-GraphGetRequest { param($tenantid, $Uri, $AsApp) }

    . $FunctionPath
}

Describe 'Invoke-ListSharepointSettings' {
    It 'reads the stable Graph endpoint using application authentication' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            [pscustomobject]@{ isSiteCreationEnabled = $true }
        }

        $request = [pscustomobject]@{
            Query = [pscustomobject]@{ tenantFilter = 'contoso.onmicrosoft.com' }
        }

        $response = Invoke-ListSharepointSettings -Request $request -TriggerMetadata $null

        $response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $response.Body.isSiteCreationEnabled | Should -BeTrue
        Should -Invoke New-GraphGetRequest -Times 1 -ParameterFilter {
            $tenantid -eq 'contoso.onmicrosoft.com' -and
            $Uri -eq 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -and
            $AsApp -eq $true
        }
    }
}
