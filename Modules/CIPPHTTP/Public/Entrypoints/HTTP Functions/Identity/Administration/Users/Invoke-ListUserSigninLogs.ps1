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

        Why the window is mandatory (Accelera, 2026-11-16): the old query was
        beta auditLogs/signIns?$filter=userId eq '<id>'&$orderby=createdDateTime desc with no date bound.
        Graph has to scan the tenant's whole retained sign-in store to answer it, so it hit Graph's own
        100 s timeout ("The request ... timed out after 100s") and CIPP returned 500. Measured on Suntec:
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

        $StartText = $Start.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
        $EndText = $End.ToString('yyyy-MM-ddTHH:mm:ssZ', $Culture)
        $Filter = "$UserClause and createdDateTime ge $StartText and createdDateTime le $EndText"
        $URI = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$top=$Top&`$orderby=createdDateTime desc"

        $Result = New-GraphGetRequest -uri $URI -tenantid $TenantFilter -noPagination $true
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to retrieve Sign In report for user $UserID : Error: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($Result)
        })
}
