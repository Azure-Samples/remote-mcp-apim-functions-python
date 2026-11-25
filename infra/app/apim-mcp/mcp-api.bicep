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
    description: 'Model Context Protocol API endpoints (Streamable HTTP)'
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

// Streamable HTTP POST endpoint - handles MCP JSON-RPC requests
resource mcpHttpPostOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-http-post'
  properties: {
    displayName: 'MCP Streamable HTTP POST'
    method: 'POST'
    urlTemplate: '/'
    description: 'Streamable HTTP endpoint for MCP JSON-RPC requests'
  }
}

// Streamable HTTP GET endpoint - optional session-based SSE stream
resource mcpHttpGetOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-http-get'
  properties: {
    displayName: 'MCP Streamable HTTP GET'
    method: 'GET'
    urlTemplate: '/'
    description: 'Streamable HTTP endpoint for opening an SSE stream'
  }
}

// Streamable HTTP DELETE endpoint - session termination
resource mcpHttpDeleteOperation 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: mcpApi
  name: 'mcp-http-delete'
  properties: {
    displayName: 'MCP Streamable HTTP DELETE'
    method: 'DELETE'
    urlTemplate: '/'
    description: 'Streamable HTTP endpoint for session termination'
  }
}

// Output the API ID for reference
output apiId string = mcpApi.id
