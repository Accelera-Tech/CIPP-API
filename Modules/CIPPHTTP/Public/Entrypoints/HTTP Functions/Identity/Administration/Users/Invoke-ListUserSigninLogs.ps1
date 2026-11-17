Function Invoke-ListUserSigninLogs {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Lists sign-in log entries for one Entra ID user inside a bounded time window, most recent first.

        Query parameters:
          tenantFilter  required
          UserID        object id (GUID) or UPN
          top           page size, default 50, max 999
          startDate     ISO 8601 UTC, inclusive. Default: endDate minus 'hours'.
          endDate       ISO 8601 UTC, inclusive. Default: now.
          hours         window length when startDate is omitted. Default 24, max 72.

        Windows wider than 6 hours are split into <=6 hour slices read concurrently through one Graph $batch
        (New-GraphBulkRequest), merged, de-duplicated by id, sorted newest first and cut to 'top'. If some slices
        fail the response is still 200 but the body becomes { Results, Metadata = { partial = true; failedSlices } }.
        If every slice fails the endpoint returns 500.

        Why the window is mandatory : the old query was
        beta auditLogs/signIns?$filter=userId eq '<id>'&$orderby=createdDateTime desc with no date bound.
        Graph has to scan the tenant's whole retained sign-in store to answer it, so it hit Graph's own
        100 s timeout ("The request ... timed out after 100s") and CIPP returned 500. Measured:
        unbounded v1.0 -> 500 after 230 s; 7-day window -> 205 s; alert +/- 3 h on v1.0 -> 3 to 51 s;
        the same windowed query on beta -> 94 s. So: v1.0, and a window of at most 72 hours.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $UserID = [string]$Request.Query.UserID

    $Top = 50
    if ($Request.Query.top) {
        $ParsedTop = 0
        if ([int]::TryParse([string]$Request.Query.top, [ref]$ParsedTop) -and $ParsedTop -gt 0) {
            $Top = [Math]::Min($ParsedTop, 999)
        }
    }

    $MaxHours = 72
    $SliceHours = 6
    $Hours = 24
    if ($Request.Query.hours) {
        $ParsedHours = 0
        if ([int]::TryParse([string]$Request.Query.hours, [ref]$ParsedHours) -and $ParsedHours -gt 0) {
            $Hours = [Math]::Min($ParsedHours, $MaxHours)
        }
    }

    try {
        if ([string]::IsNullOrWhiteSpace($UserID)) { throw 'UserID is required.' }

        # The id goes into an OData filter: accept only a GUID or a UPN-shaped value, never free text.
        $Guid = [guid]::Empty
        if ([guid]::TryParse($UserID, [ref]$Guid)) {
            $UserClause = "userId eq '$($Guid.ToString())'"
        } elseif ($UserID -match '^[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') {
            $UserClause = "userPrincipalName eq '$($UserID.Replace("'", "''"))'"
        } else {
            throw "UserID '$UserID' is neither an object id nor a user principal name."
        }

        $Culture = [System.Globalization.CultureInfo]::InvariantCulture
        $Styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        $End = [datetime]::UtcNow
        if ($Request.Query.endDate) {
            $ParsedEnd = [datetime]::MinValue
            if (-not [datetime]::TryParse([string]$Request.Query.endDate, $Culture, $Styles, [ref]$ParsedEnd)) { throw "endDate '$($Request.Query.endDate)' is not a date." }
            $End = $ParsedEnd
        }
        $Start = $End.AddHours(-$Hours)
        if ($Request.Query.startDate) {
            $ParsedStart = [datetime]::MinValue
            if (-not [datetime]::TryParse([string]$Request.Query.startDate, $Culture, $Styles, [ref]$ParsedStart)) { throw "startDate '$($Request.Query.startDate)' is not a date." }
            $Start = $ParsedStart
        }
        if ($Start -ge $End) { throw 'startDate must be before endDate.' }
        if (($End - $Start).TotalHours -gt $MaxHours) {
            # A wider window is what made this endpoint time out. Clamp to the most recent part of it.
            $Start = $End.AddHours(-$MaxHours)
        }

        # Latency scales with the window Graph has to scan, so a window wider than $SliceHours is cut into
        # slices that Graph answers concurrently in one $batch. Slices are half-open [from, to) except the
        # last, which closes on $End; the id dedupe below is a second guard against a boundary row.
        $Slices = [System.Collections.Generic.List[object]]::new()
        $Cursor = $Start
        while ($Cursor -lt $End) {
            $SliceEnd = $Cursor.AddHours($SliceHours)
            $IsLast = $SliceEnd -ge $End
            if ($IsLast) { $SliceEnd = $End }
            $Slices.Add([pscustomobject]@{
                    From   = $Cursor
                    To     = $SliceEnd
                    Closed = $IsLast
                })
            $Cursor = $SliceEnd
        }
        $SliceQuery = {
            param($Slice)
            $FromText = $Slice.From.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
            $ToText = $Slice.To.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
            $Operator = if ($Slice.Closed) { 'le' } else { 'lt' }
            "$UserClause and createdDateTime ge $FromText and createdDateTime $Operator $ToText"
        }

        $Partial = $false
        $FailedSlices = [System.Collections.Generic.List[object]]::new()
        if ($Slices.Count -eq 1) {
            $Filter = & $SliceQuery $Slices[0]
            $URI = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$top=$Top&`$orderby=createdDateTime desc"
            $Result = New-GraphGetRequest -uri $URI -tenantid $TenantFilter -noPagination $true
        } else {
            $Requests = for ($i = 0; $i -lt $Slices.Count; $i++) {
                $Filter = & $SliceQuery $Slices[$i]
                [pscustomobject]@{
                    id     = "slice$i"
                    method = 'GET'
                    url    = "/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($Filter))&`$top=$Top&`$orderby=createdDateTime%20desc"
                }
            }
            $Responses = @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -NoPaginateIds @($Requests.id) -Version 'v1.0')

            $Rows = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $Slices.Count; $i++) {
                $Response = $Responses | Where-Object { $_.id -eq "slice$i" } | Select-Object -First 1
                $Status = if ($Response) { $Response.status -as [int] } else { 0 }
                if ($Status -ge 200 -and $Status -lt 300) {
                    foreach ($Row in @($Response.body.value)) { if ($null -ne $Row) { $Rows.Add($Row) } }
                } else {
                    $Reason = if (-not $Response) { 'no reply in the batch response' } elseif ($Response.body.error.message) { "HTTP $Status`: $($Response.body.error.message)" } else { "HTTP $Status" }
                    $FailedSlices.Add([ordered]@{
                            from   = $Slices[$i].From.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
                            to     = $Slices[$i].To.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
                            reason = $Reason
                        })
                }
            }
            if ($FailedSlices.Count -eq $Slices.Count) {
                throw "All $($Slices.Count) time slices failed. First error: $($FailedSlices[0].reason)"
            }
            $Partial = $FailedSlices.Count -gt 0

            $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $Unique = foreach ($Row in $Rows) {
                if ([string]::IsNullOrEmpty([string]$Row.id) -or $Seen.Add([string]$Row.id)) { $Row }
            }
            $Result = @($Unique | Sort-Object -Property { [datetime]$_.createdDateTime } -Descending | Select-Object -First $Top)
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to retrieve Sign In report for user $UserID : Error: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    # A complete read keeps the original body shape (a bare array of sign-ins). A read where some slices
    # failed is returned as { Results, Metadata } so the gap is visible to the caller.
    $Body = if ($Partial) {
        @{
            Results  = @($Result)
            Metadata = @{ partial = $true; failedSlices = @($FailedSlices) }
        }
    } else {
        @($Result)
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
