extension microsoftGraphV1

@description('The name of the Entra application')
param entraAppUniqueName string

@description('The display name of the Entra application')
param entraAppDisplayName string

@description('Tenant ID where the application is registered')
param tenantId string = tenant().tenantId

@description('The OAuth callback URL for the API Management service')
param apimOauthCallback string

@description('The principle id of the user-assigned managed identity')
param userAssignedIdentityPrincipleId string

var loginEndpoint = environment().authentication.loginEndpoint
var issuer = '${loginEndpoint}${tenantId}/v2.0'

resource entraApp 'Microsoft.Graph/applications@v1.0' = {
  displayName: entraAppDisplayName
  uniqueName: entraAppUniqueName
  api: {
    oauth2PermissionScopes: [
      {
        id: guid(entraAppUniqueName, 'access_as_user') // Generates a deterministic GUID
        adminConsentDescription: 'Allow the application to access resources on behalf of the signed-in user.'
        adminConsentDisplayName: 'Access resources on behalf of signed-in user'
        isEnabled: true
        type: 'User'
        userConsentDescription: 'Allow the application to access resources on your behalf.'
        userConsentDisplayName: 'Access resources on your behalf'
        value: 'access_as_user'
      }
    ]
  }
  web: {
    redirectUris: [
      apimOauthCallback
    ]
  }
  requiredResourceAccess: [
    {
      resourceAppId: '00000003-0000-0000-c000-000000000000'
      resourceAccess: [
        {
          id: 'e1fe6dd8-ba31-4d61-89e7-88639da4683d' // User.Read
          type: 'Scope'
        }
      ]
    }
  ]

  resource fic 'federatedIdentityCredentials@v1.0' = {
    name: '${entraApp.uniqueName}/msiAsFic'
    description: 'Trust the user-assigned MI as a credential for the app'
    audiences: [
       'api://AzureADTokenExchange'
    ]
    issuer: issuer
    subject: userAssignedIdentityPrincipleId
  }
}

// Update the application with its own appId in the identifier URI
resource entraResourceAppUpdate 'Microsoft.Graph/applications@v1.0' = {
  identifierUris: [
    'api://${entraApp.appId}'
  ]
  // Keep all other properties the same as the original resource
  displayName: entraAppDisplayName
  uniqueName: entraAppUniqueName
  api: entraApp.api
  web: entraApp.web
  requiredResourceAccess: entraApp.requiredResourceAccess
}

// Outputs
output entraAppId string = entraApp.appId
output entraAppTenantId string = tenantId
