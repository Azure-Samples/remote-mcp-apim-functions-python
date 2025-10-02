@description('The name of the API Management service')
param apimServiceName string

@description('The name of the Function App hosting the MCP endpoints')
param functionAppName string

// Get reference to the existing APIM service
resource apimService 'Microsoft.ApiManagement/service@2023-05-01-preview' existing = {
  name: apimServiceName
}

// Get reference to the Function App
resource functionApp 'Microsoft.Web/sites@2023-12-01' existing = {
  name: functionAppName
}

// Create a named value in APIM to store the function key
resource functionHostKeyNamedValue 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apimService
  name: 'function-host-key'
  properties: {
    displayName: 'function-host-key'
    secret: true
    value: listKeys('${functionApp.id}/host/default', functionApp.apiVersion).masterKey
  }
}

// Create the MCP API definition in APIM
resource mcpApi 'Microsoft.ApiManagement/service/apis@2023-05-01-preview' = {
  parent: apimService
  name: 'mcp'
  properties: {
    displayName: 'MCP API'
    description: 'Model Context Protocol API endpoints'
    subscriptionRequired: false
    path: 'mcp'
    protocols: [
      'https'
    ]
    serviceUrl: 'https://${functionApp.properties.defaultHostName}/runtime/webhooks/mcp'
  }
  dependsOn: [
    functionHostKeyNamedValue
  ]
}

// Apply policy at the API level for all operations
resource mcpApiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-05-01-preview' = {
  parent: mcpApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('mcp-api.policy.xml')
  }
}

// Create the SSE endpoint operation
resource mcpSseOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-sse'
  properties: {
    displayName: 'MCP SSE Endpoint'
    method: 'GET'
    urlTemplate: '/sse'
    description: 'Server-Sent Events endpoint for MCP Server'
  }
}

// Create the message endpoint operation
resource mcpMessageOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-message'
  properties: {
    displayName: 'MCP Message Endpoint'
    method: 'POST'
    urlTemplate: '/message'
    description: 'Message endpoint for MCP Server'
  }
}

// Create a test endpoint for debugging
resource mcpTestMessageOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-test-message'
  properties: {
    displayName: 'MCP Test Message Endpoint'
    method: 'POST'
    urlTemplate: '/test-message'
    description: 'Test endpoint for debugging the message flow'
  }
}

// Output the API ID for reference
output apiId string = mcpApi.id
