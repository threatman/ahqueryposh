# from https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/run-advanced-query-sample-powershell 
# follow the steps to register an app in Azure AD first. Then, paste in your tenant ID, app ID and app secret below:
$tenantId = '00000000-0000-0000-0000-000000000000' # Paste your own tenant ID here
$appId = '11111111-1111-1111-1111-111111111111' # Paste your own app ID here
$appSecret = '22222222-2222-2222-2222-222222222222' # Paste your own app secret here

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$body = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
$aadToken = $response.access_token

# Paste your own query here. Reference at https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/querying-application-control-events-centrally-using-advanced-hunting 

$query = 'MiscEvents
| where EventTime > ago(7d) and ActionType startswith "AppControl"
| summarize Machines=dcount(ComputerName) by ActionType
| order by Machines desc' 

$url = "https://api.securitycenter.windows.com/api/advancedqueries/run"
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $aadToken" 
}
$body = ConvertTo-Json -InputObject @{ 'Query' = $query }
$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$response =  $webResponse | ConvertFrom-Json
$results = $response.Results
$schema = $response.Schema