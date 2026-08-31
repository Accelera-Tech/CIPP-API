Function Invoke-ListSharepointSettings {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Admin.Read
    .DESCRIPTION
        Retrieves SharePoint Online tenant-level settings and configuration.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    #  XXX - Seems to be an unused endpoint? -Bobby


    # Interact with query parameters or the body of the request.
    $Tenant = $Request.Query.tenantFilter
    $Request = New-GraphGetRequest -tenantid $Tenant -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -AsApp $true

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($Request)
        })

}
