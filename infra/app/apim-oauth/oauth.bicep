@description('The name of the API Management service')
param apimServiceName string

@description('The Azure region for resources')
param location string

// Parameters for Named Values
@description('The required scopes for authorization')
param oauthScopes string

@description('The principle id of the user-assigned managed identity for Entra app')
param entraAppUserAssignedIdentityPrincipleId string

@description('The client ID of the user-assigned managed identity for Entra app')
param entraAppUserAssignedIdentityClientId string

@description('The name of the Entra application')
param entraAppUniqueName string

@description('The display name of the Entra application')
param entraAppDisplayName string

@description('The name of the MCP Server to display in the consent page')
param mcpServerName string = 'MCP Server'

@description('The CosmosDB account endpoint')
param cosmosDbEndpoint string

@description('The CosmosDB database name')
param cosmosDbDatabaseName string

@description('The CosmosDB container name for client registrations')
param cosmosDbContainerName string

resource apimService 'Microsoft.ApiManagement/service@2021-08-01' existing = {
  name: apimServiceName
}

// Create user-assigned managed identity for crypto script
resource cryptoScriptIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' = {
  name: '${apimServiceName}-crypto-script-identity'
  location: location
}

module entraApp './entra-app.bicep' = {
  name: 'entraApp'
  params:{
    entraAppUniqueName: entraAppUniqueName
    entraAppDisplayName: entraAppDisplayName
    apimOauthCallback: '${apimService.properties.gatewayUrl}/oauth-callback'
    userAssignedIdentityPrincipleId: entraAppUserAssignedIdentityPrincipleId
  }
}

// Role assignment for the crypto script identity to manage APIM named values
resource cryptoScriptApimRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, cryptoScriptIdentity.id, 'APIM Contributor')
  scope: apimService
  properties: {
    principalId: cryptoScriptIdentity.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '312a565d-c81f-4fd8-895a-4e21e48d571c')
    principalType: 'ServicePrincipal'
  }
}

// Using a deployment script to generate cryptographically secure values for AES encryption
// Key is 32 bytes (256-bit) and IV is 16 bytes (128-bit)
resource cryptoValuesScript 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: 'generateCryptoValues'
  location: location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${cryptoScriptIdentity.id}': {}
    }
  }
  properties: {
    azPowerShellVersion: '7.0'
    timeout: 'PT30M'
    retentionInterval: 'P1D'
    environmentVariables: [
      {
        name: 'APIM_NAME'
        value: apimServiceName
      }
      {
        name: 'RESOURCEGROUP_NAME'
        value: resourceGroup().name
      }
      {
        name: 'SUBSCRIPTION_ID'
        value: subscription().subscriptionId
      }
    ]
    scriptContent: '''
      # Set subscription context
      Set-AzContext -Subscription $env:SUBSCRIPTION_ID
      
      # Generate random 32 bytes (256-bit) key for AES-256
      $key = New-Object byte[] 32
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      $rng.GetBytes($key)
      $keyBase64 = [Convert]::ToBase64String($key)
      
      # Generate random 16 bytes (128-bit) IV
      $iv = New-Object byte[] 16
      $rng.GetBytes($iv)
      $ivBase64 = [Convert]::ToBase64String($iv)
      
      # Create APIM context with subscription ID
      $apimContext = New-AzApiManagementContext -ResourceGroupName $env:RESOURCEGROUP_NAME -ServiceName $env:APIM_NAME
      
      # Set the values in APIM named values
      New-AzApiManagementNamedValue -Context $apimContext -NamedValueId "EncryptionKey" -Name "EncryptionKey" -Value $keyBase64 -Secret
      New-AzApiManagementNamedValue -Context $apimContext -NamedValueId "EncryptionIV" -Name "EncryptionIV" -Value $ivBase64 -Secret
    '''
  }
}

// Define the Named Values
resource EntraIDTenantIdNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'EntraIDTenantId'
  properties: {
    displayName: 'EntraIDTenantId'
    value: entraApp.outputs.entraAppTenantId
    secret: false
  }
}

resource EntraIDClientIdNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'EntraIDClientId'
  properties: {
    displayName: 'EntraIDClientId'
    value: entraApp.outputs.entraAppId
    secret: false
  }
}

resource EntraIdFicClientIdNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'EntraIDFicClientId'
  properties: {
    displayName: 'EntraIdFicClientId'
    value: entraAppUserAssignedIdentityClientId
    secret: false
  }
}

resource OAuthCallbackUriNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'OAuthCallbackUri'
  properties: {
    displayName: 'OAuthCallbackUri'
    value: '${apimService.properties.gatewayUrl}/oauth-callback'
    secret: false
  }
}

resource OAuthScopesNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'OAuthScopes'
  properties: {
    displayName: 'OAuthScopes'
    value: oauthScopes
    secret: false
  }
}


resource McpClientIdNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'McpClientId'
  properties: {
    displayName: 'McpClientId'
    value: entraApp.outputs.entraAppId
    secret: false
  }
}

resource APIMGatewayURLNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'APIMGatewayURL'
  properties: {
    displayName: 'APIMGatewayURL'
    value: apimService.properties.gatewayUrl
    secret: false
  }
}

resource MCPServerNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'MCPServerName'
  properties: {
    displayName: 'MCPServerName'
    value: mcpServerName
    secret: false
  }
}

// CosmosDB Named Values
resource CosmosDbEndpointNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'CosmosDbEndpoint'
  properties: {
    displayName: 'CosmosDbEndpoint'
    value: cosmosDbEndpoint
    secret: false
  }
}

resource CosmosDbDatabaseNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'CosmosDbDatabase'
  properties: {
    displayName: 'CosmosDbDatabase'
    value: cosmosDbDatabaseName
    secret: false
  }
}

resource CosmosDbContainerNamedValue 'Microsoft.ApiManagement/service/namedValues@2021-08-01' = {
  parent: apimService
  name: 'CosmosDbContainer'
  properties: {
    displayName: 'CosmosDbContainer'
    value: cosmosDbContainerName
    secret: false
  }
}

// Create the OAuth API
resource oauthApi 'Microsoft.ApiManagement/service/apis@2021-08-01' = {
  parent: apimService
  name: 'oauth'
  properties: {
    displayName: 'OAuth'
    description: 'OAuth 2.0 Authentication API'
    subscriptionRequired: false
    path: ''
    protocols: [
      'https'
    ]
    serviceUrl: 'https://login.microsoftonline.com/${entraApp.outputs.entraAppTenantId}/oauth2/v2.0'
  }
}

// Add a GET operation for the authorization endpoint
resource oauthAuthorizeOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'authorize'
  properties: {
    displayName: 'Authorize'
    method: 'GET'
    urlTemplate: '/authorize'
    description: 'OAuth 2.0 authorization endpoint'
  }
}

// Add policy for the authorize operation
resource oauthAuthorizePolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthAuthorizeOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('authorize.policy.xml')
  }
}

// Add a POST operation for the token endpoint
resource oauthTokenOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'token'
  properties: {
    displayName: 'Token'
    method: 'POST'
    urlTemplate: '/token'
    description: 'OAuth 2.0 token endpoint'
  }
}

// Add policy for the token operation
resource oauthTokenPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthTokenOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('token.policy.xml')
  }
}

// Add a GET operation for the OAuth callback endpoint
resource oauthCallbackOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'oauth-callback'
  properties: {
    displayName: 'OAuth Callback'
    method: 'GET'
    urlTemplate: '/oauth-callback'
    description: 'OAuth 2.0 callback endpoint to handle authorization code flow'
  }
}

// Add policy for the OAuth callback operation
resource oauthCallbackPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthCallbackOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('oauth-callback.policy.xml')
  }
  dependsOn: [
    cryptoValuesScript
  ]
}

// Add a POST operation for the register endpoint
resource oauthRegisterOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'register'
  properties: {
    displayName: 'Register'
    method: 'POST'
    urlTemplate: '/register'
    description: 'OAuth 2.0 client registration endpoint'
  }
}

// Add policy for the register operation
resource oauthRegisterPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthRegisterOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('register.policy.xml')
  }
}

// Add a OPTIONS operation for the register endpoint
resource oauthRegisterOptionsOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'register-options'
  properties: {
    displayName: 'Register Options'
    method: 'OPTIONS'
    urlTemplate: '/register'
    description: 'CORS preflight request handler for register endpoint'
  }
}

// Add policy for the register options operation
resource oauthRegisterOptionsPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthRegisterOptionsOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('register-options.policy.xml')
  }
}

// Add a OPTIONS operation for the OAuth metadata endpoint
resource oauthMetadataOptionsOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'oauthmetadata-options'
  properties: {
    displayName: 'OAuth Metadata Options'
    method: 'OPTIONS'
    urlTemplate: '/.well-known/oauth-authorization-server'
    description: 'CORS preflight request handler for OAuth metadata endpoint'
  }
}

// Add policy for the OAuth metadata options operation
resource oauthMetadataOptionsPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthMetadataOptionsOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('oauthmetadata-options.policy.xml')
  }
}

// Add a GET operation for the OAuth metadata endpoint
resource oauthMetadataGetOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'oauthmetadata-get'
  properties: {
    displayName: 'OAuth Metadata Get'
    method: 'GET'
    urlTemplate: '/.well-known/oauth-authorization-server'
    description: 'OAuth 2.0 metadata endpoint'
  }
}

// Add policy for the OAuth metadata get operation
resource oauthMetadataGetPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthMetadataGetOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('oauthmetadata-get.policy.xml')
  }
}

// Add a OPTIONS operation for the OAuth Protected Resource Metadata endpoint
resource oauthProtectedResourceMetadataOptionsOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'oauth-protected-resource-metadata-options'
  properties: {
    displayName: 'OAuth Protected Resource Metadata Options'
    method: 'OPTIONS'
    urlTemplate: '/.well-known/oauth-protected-resource'
    description: 'CORS preflight request handler for OAuth Protected Resource Metadata endpoint'
  }
}

// Add policy for the OAuth Protected Resource Metadata options operation
resource oauthProtectedResourceMetadataOptionsPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthProtectedResourceMetadataOptionsOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('oauth-prm-options.policy.xml')
  }
}

// Add a GET operation for the OAuth Protected Resource Metadata endpoint
resource oauthProtectedResourceMetadataGetOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'oauth-protected-resource-metadata-get'
  properties: {
    displayName: 'OAuth Protected Resource Metadata Get'
    method: 'GET'
    urlTemplate: '/.well-known/oauth-protected-resource'
    description: 'OAuth 2.0 Protected Resource Metadata endpoint'
  }
}

// Add policy for the OAuth Protected Resource Metadata get operation
resource oauthProtectedResourceMetadataGetPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthProtectedResourceMetadataGetOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('oauth-prm-get.policy.xml')
  }
}

// Add a GET operation for the consent endpoint
resource oauthConsentGetOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'consent-get'
  properties: {
    displayName: 'Consent Page'
    method: 'GET'
    urlTemplate: '/consent'
    description: 'Client consent page endpoint'
  }
}

// Add policy for the consent GET operation
resource oauthConsentGetPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthConsentGetOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('consent.policy.xml')
  }
}

// Add a POST operation for the consent endpoint
resource oauthConsentPostOperation 'Microsoft.ApiManagement/service/apis/operations@2021-08-01' = {
  parent: oauthApi
  name: 'consent-post'
  properties: {
    displayName: 'Consent Submission'
    method: 'POST'
    urlTemplate: '/consent'
    description: 'Client consent submission endpoint'
  }
}

// Add policy for the consent POST operation
resource oauthConsentPostPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2021-08-01' = {
  parent: oauthConsentPostOperation
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('consent.policy.xml')
  }
}
output apiId string = oauthApi.id
