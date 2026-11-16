Function Invoke-ListSignIns {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.AuditLog.Read
    .DESCRIPTION
        Lists recent sign-in log entries for a tenant, filterable by various criteria. Supports AllTenants queries.

        Deprecated: use ListGraphRequest with Endpoint=auditLogs/signIns instead, which supports $filter, $top,
        $orderby, and manualPagination with nextLink continuation. This endpoint returns at most one page of
        results and will be removed in a future release.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APINAME = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers


    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.tenantFilter
    $Days = $Request.Query.Days ?? 7
    # A tenant-wide signIns query over a long range cannot finish inside Graph's 100 s limit. Cap it.
    $ParsedDays = 0
    $Days = if ([int]::TryParse([string]$Days, [ref]$ParsedDays) -and $ParsedDays -gt 0) { [Math]::Min($ParsedDays, 7) } else { 7 }
    $FailedLogonsOnly = $Request.Query.failedLogonsOnly
    $FailureThreshold = $Request.Query.FailureThreshold
    $Filter = $Request.Query.Filter

    try {
        if ($FailedLogonsOnly -eq 'true' -or $FailedLogonsOnly -eq $true) {
            $FailedLogons = ' and (status/errorCode eq 50126)'
        }

        $Filters = if ($Filter) {
            $Filter
        } else {
            $ts = (Get-Date).AddDays(-$Days).ToUniversalTime()
            $endTime = $ts.ToString('yyyy-MM-dd')
            "createdDateTime ge $($endTime) and userDisplayName ne 'On-Premises Directory Synchronization Service Account' $FailedLogons"
        }
        Write-Host $Filters
        Write-LogMessage -headers $Headers -API $APINAME -message 'Retrieved sign in report' -Sev 'Debug' -tenant $TenantFilter

        # Single page only: full-range paging belongs to ListGraphRequest with manualPagination.
        # v1.0, not beta (2026-11-16): the same windowed signIns query measured 3-51 s on v1.0 and 94 s on beta,
        # and beta routinely ran past Graph's 100 s timeout, which CIPP surfaced as HTTP 500.
        $GraphRequest = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$($Filters)&`$top=999" -tenantid $TenantFilter -noPagination $true -ErrorAction Stop
        $response = $GraphRequest | Select-Object *,
        @{l = 'additionalDetails'; e = { $_.status.additionalDetails } } ,
        @{l = 'errorCode'; e = { $_.status.errorCode } },
        @{l = 'locationcipp'; e = { "$($_.location.city) - $($_.location.countryOrRegion)" } }

        if ($FailedLogonsOnly -and $FailureThreshold -and $FailureThreshold -gt 0) {
            $response = $response | Group-Object -Property userPrincipalName | Where-Object { $_.Count -ge $FailureThreshold } | Select-Object -ExpandProperty Group
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @($response)
                Headers    = @{ 'Deprecation' = 'true' }
            })
    } catch {
        Write-LogMessage -headers $Request.Headers -API $APINAME -message "Failed to retrieve Sign In report: $($_.Exception.message) " -Sev 'Error' -tenant $TenantFilter
        return ([HttpResponseContext]@{
                StatusCode = '500'
                Body       = $(Get-NormalizedError -message $_.Exception.message)
            })
    }

}
