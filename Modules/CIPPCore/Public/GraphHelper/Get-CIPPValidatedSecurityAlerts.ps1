function Get-CIPPValidatedSecurityAlerts {
    <#
    .FUNCTIONALITY
    Internal
    .DESCRIPTION
    Fully buffered security-alert read. No partial pages escape on failure.
    The 25-second HTTP/pagination budget leaves room inside the caller's 30-second deadline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $alerts = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $next = $Uri.AbsoluteUri
    $page = 0
    do {
        $pageUri = [uri]$next
        if ($pageUri.Scheme -ne 'https' -or $pageUri.Host -ne 'graph.microsoft.com' -or
            $pageUri.AbsolutePath -ne '/beta/security/alerts' -or $pageUri.Port -ne 443 -or
            $pageUri.UserInfo -or $pageUri.Fragment -or !$visited.Add($next)) {
            throw 'Security alert feed rejected an invalid or repeated page URL.'
        }
        $page++
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $remaining = [math]::Floor(25 - $clock.Elapsed.TotalSeconds)
            if ($remaining -lt 1) { throw 'Security alert feed exceeded its completeness-check deadline.' }
            $status = $null
            $responseHeaders = @{}
            $data = $null
            try {
                $data = Invoke-CIPPRestMethod -Uri $pageUri -Method GET -Headers $Headers -ContentType 'application/json; charset=utf-8' -StatusCodeVariable status -ResponseHeadersVariable responseHeaders -TimeoutSec ([math]::Min(12, $remaining)) -ErrorAction Stop
                $warning = @($responseHeaders['Warning']) -join ', '
                $requestId = @($responseHeaders['request-id']) -join ', '
                $valid = $status -eq 200 -and [string]::IsNullOrWhiteSpace($warning) -and
                    $null -ne $data -and $data -is [pscustomobject] -and
                    $data.PSObject.Properties.Name -notcontains 'error' -and
                    $data.PSObject.Properties.Name -contains 'value' -and $data.value -is [array]
                if ($valid) {
                    foreach ($alert in $data.value) {
                        if ($null -eq $alert -or $alert -isnot [pscustomobject] -or
                            $alert.id -isnot [string] -or [string]::IsNullOrWhiteSpace($alert.id) -or
                            $alert.status -notin @('newAlert', 'inProgress', 'resolved', 'dismissed', 'unknownFutureValue') -or
                            $alert.azureTenantId -isnot [string] -or [string]::IsNullOrWhiteSpace($alert.azureTenantId)) {
                            $valid = $false
                            break
                        }
                        # Tenant aliases remain supported; GUID callers additionally get exact tenant validation.
                        $tenantGuid = [guid]::Empty
                        if ([guid]::TryParse($TenantId, [ref]$tenantGuid) -and $alert.azureTenantId -ne $TenantId) {
                            $valid = $false
                            break
                        }
                    }
                    if ($data.PSObject.Properties.Name -contains '@odata.nextLink' -and
                        ($data.'@odata.nextLink' -isnot [string] -or [string]::IsNullOrWhiteSpace($data.'@odata.nextLink'))) {
                        $valid = $false
                    }
                }
                $diagnostic = @{
                    tenant = $TenantId; page = $page; attempt = $attempt; upstreamStatus = $status
                    providerWarning = $warning; requestId = $requestId
                    elapsedMs = $clock.ElapsedMilliseconds; complete = $valid
                } | ConvertTo-Json -Compress
                Write-Information "SecurityAlertFeed: $diagnostic"
                if (!$valid) { throw 'Security alert feed returned incomplete or invalid upstream data.' }
                break
            } catch {
                # Preserve safe diagnostic context, without tokens, response bodies or user details.
                Write-Warning "SecurityAlertFeed read failed: tenant=$TenantId page=$page attempt=$attempt upstreamStatus=$status elapsedMs=$($clock.ElapsedMilliseconds)"
                if ($attempt -eq 2 -or $clock.Elapsed.TotalSeconds -ge 24) {
                    throw 'Security alert feed could not verify complete upstream data within its retry budget.'
                }
            }
        }
        foreach ($alert in $data.value) { $alerts.Add($alert) }
        $next = $data.'@odata.nextLink'
    } while ($next)
    return $alerts.ToArray()
}
