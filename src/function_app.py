from dataclasses import dataclass
import json
import logging
import base64
import requests
from typing import Dict, Any, Optional

import azure.functions as func
import jwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives import serialization

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Constants for the Azure Blob Storage container, file, and blob path
_SNIPPET_NAME_PROPERTY_NAME = "snippetname"
_SNIPPET_PROPERTY_NAME = "snippet"
_BLOB_PATH = "snippets/{mcptoolargs." + _SNIPPET_NAME_PROPERTY_NAME + "}.json"


def mask_secret(secret: str, show: int = 4) -> str:
    """Redacts a secret value for safe logging."""
    if not secret:
        return ""
    return f"{secret[:show]}...{secret[-show:]}" if len(secret) > show * 2 else "***"


def validate_jwt_token(access_token: str, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict[str, Any]:
    """
    Validates a JWT token with signature verification.
    
    Args:
        access_token (str): The JWT token to validate
        audience (str, optional): Expected audience claim
        issuer (str, optional): Expected issuer claim
        
    Returns:
        Dict[str, Any]: Dictionary containing validation result and token claims
    """
    try:
        logging.info("Starting JWT token validation")
        logging.info(access_token)
        # Decode the token header to get algorithm and key ID
        unverified_header = jwt.get_unverified_header(access_token)
        algorithm = unverified_header.get('alg', 'RS256')
        kid = unverified_header.get('kid')
        
        logging.info(f"Token algorithm: {algorithm}, Key ID: {kid}")
        
        # First, decode without verification to get claims for issuer discovery
        unverified_claims = jwt.decode(access_token, options={"verify_signature": False})
        token_issuer = unverified_claims.get('iss')
        
        logging.info(f"Token issuer: {token_issuer}")
        
        # Try to get the signing key
        signing_key = None
        
        if token_issuer:
            try:
                # Try to discover JWKS endpoint from OpenID configuration
                if token_issuer.endswith('/'):
                    token_issuer = token_issuer.rstrip('/')
                
                # Common patterns for JWKS URLs
                jwks_urls = [
                    f"{token_issuer}/.well-known/jwks.json",
                    f"{token_issuer}/common/discovery/keys",
                    f"{token_issuer}/discovery/keys"
                ]
                
                # Try Microsoft Entra ID patterns
                if 'login.microsoftonline.com' in token_issuer or 'sts.windows.net' in token_issuer:
                    tenant_id = token_issuer.split('/')[-1]
                    jwks_urls.insert(0, f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys")
                    jwks_urls.insert(1, f"https://login.microsoftonline.com/common/discovery/keys")
                
                # Try to fetch the JWKS
                for jwks_url in jwks_urls:
                    try:
                        logging.info(f"Trying JWKS URL: {jwks_url}")
                        jwks_client = PyJWKClient(jwks_url)
                        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
                        logging.info(f"Successfully obtained signing key from: {jwks_url}")
                        break
                    except Exception as e:
                        logging.warning(f"Failed to get signing key from {jwks_url}: {str(e)}")
                        continue
                        
            except Exception as e:
                logging.warning(f"Failed to discover JWKS endpoint: {str(e)}")
        
        if not signing_key:
            return {
                "valid": False,
                "error": "Unable to obtain signing key for token validation",
                "claims": unverified_claims
            }
        
        # Validate the token with signature verification
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "verify_aud": False,  # Default to False, can be overridden
            "verify_iss": False,   # Default to True, can be overridden
        }
        
        # Set verification options based on provided parameters
        if audience:
            options["verify_aud"] = False
        if issuer:
            options["verify_iss"] = True
            
        decode_kwargs = {
            "algorithms": [algorithm],
            "options": options
        }
        
        if audience:
            decode_kwargs["audience"] = audience
        if issuer:
            decode_kwargs["issuer"] = issuer
            
        # Decode and verify the token
        verified_claims = jwt.decode(
            access_token,
            signing_key.key,
            **decode_kwargs
        )
        
        logging.info("JWT token validation successful")
        return {
            "valid": True,
            "claims": verified_claims,
            "header": unverified_header
        }
        
    except jwt.ExpiredSignatureError:
        return {
            "valid": False,
            "error": "Token has expired",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }
    except jwt.InvalidAudienceError:
        expected_aud = audience if audience else "not specified"
        token_aud = unverified_claims.get('aud') if 'unverified_claims' in locals() else "unknown"
        return {
            "valid": False,
            "error": f"Invalid audience. Expected: '{expected_aud}', Found in token: '{token_aud}'",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }
    except jwt.InvalidIssuerError:
        return {
            "valid": False,
            "error": "Invalid issuer",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }
    except jwt.InvalidSignatureError:
        return {
            "valid": False,
            "error": "Invalid token signature",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }
    except jwt.InvalidTokenError as e:
        return {
            "valid": False,
            "error": f"Invalid token: {str(e)}",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }
    except Exception as e:
        logging.error(f"Unexpected error during JWT validation: {str(e)}")
        return {
            "valid": False,
            "error": f"Validation error: {str(e)}",
            "claims": unverified_claims if 'unverified_claims' in locals() else None
        }


@dataclass
class ToolProperty:
    propertyName: str
    propertyType: str
    description: str


# Define the tool properties using the ToolProperty class
tool_properties_save_snippets_object = [
    ToolProperty(_SNIPPET_NAME_PROPERTY_NAME, "string", "The name of the snippet."),
    ToolProperty(_SNIPPET_PROPERTY_NAME, "string", "The content of the snippet."),
]

tool_properties_get_snippets_object = [ToolProperty(_SNIPPET_NAME_PROPERTY_NAME, "string", "The name of the snippet.")]

# Convert the tool properties to JSON
tool_properties_save_snippets_json = json.dumps([prop.__dict__ for prop in tool_properties_save_snippets_object])
tool_properties_get_snippets_json = json.dumps([prop.__dict__ for prop in tool_properties_get_snippets_object])

@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="hello_mcp",
    description="Hello world.",
    toolProperties="[]",
)
def hello_mcp(context) -> str:
    """
    A simple function that returns a greeting message.

    Args:
        context: The trigger context (not used in this function).

    Returns:
        str: A greeting message.
    """
    return "Hello I am MCPTool!"

@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="validate_token",
    description="Performs JWT token validation.",
    toolProperties="[]",
)
def validate_token(context) -> str:
    """
    A function that validates a JWT token and returns validation results.

    Args:
        context: The trigger context containing the bearer token.

    Returns:
        str: Validation result message with token details.
    """
    # Parse context
    try:
        context_obj = json.loads(context) if isinstance(context, str) else context
    except Exception as e:
        logging.error("Invalid context JSON: %s", e)
        return "Invalid request: context is not valid JSON."

    # Validate arguments
    arguments = context_obj.get('arguments')
    if not isinstance(arguments, dict):
        return "Invalid request: 'arguments' object is missing."

    # Get bearer token
    bearer_token = arguments.get('bearerToken')
    if not bearer_token:
        return "Invalid request: 'bearerToken' is missing."

    # Normalize access token from bearerToken (supports raw token or JSON with access_token)
    access_token = None
    if isinstance(bearer_token, str):
        try:
            token_data = json.loads(bearer_token)
            access_token = token_data.get('access_token')
        except Exception:
            # Treat the string itself as the access token (e.g., JWT or opaque token)
            access_token = bearer_token
    elif isinstance(bearer_token, dict):
        access_token = bearer_token.get('access_token')

    if not access_token:
        return "Invalid request: 'access_token' not found in 'bearerToken'."

    logging.info("Received access token (%d chars): %s", len(access_token), mask_secret(access_token))
    
    # Validate the JWT token
    validation_result = validate_jwt_token(access_token)
    
    # Format the response
    if validation_result["valid"]:
        claims = validation_result.get("claims", {})
        response = {
            "status": "valid",
            "message": "JWT token is valid and signature verified",
            "token_info": {
                "issuer": claims.get("iss"),
                "audience": claims.get("aud"),
                "subject": claims.get("sub"),
                "expiry": claims.get("exp"),
                "issued_at": claims.get("iat"),
                "not_before": claims.get("nbf"),
                "token_id": claims.get("jti"),
                "scope": claims.get("scope"),
                "client_id": claims.get("client_id"),
                "app_id": claims.get("appid")
            },
            "header": validation_result.get("header")
        }
        
        # Remove None values from token_info
        response["token_info"] = {k: v for k, v in response["token_info"].items() if v is not None}
        
        return json.dumps(response, indent=2)
    else:
        error_response = {
            "status": "invalid",
            "error": validation_result.get("error", "Unknown validation error"),
            "claims": validation_result.get("claims")
        }
        return json.dumps(error_response, indent=2)


@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="get_snippet",
    description="Retrieve a snippet by name.",
    toolProperties=tool_properties_get_snippets_json,
)
@app.generic_input_binding(arg_name="file", type="blob", connection="AzureWebJobsStorage", path=_BLOB_PATH)
def get_snippet(file: func.InputStream, context) -> str:
    """
    Retrieves a snippet by name from Azure Blob Storage.

    Args:
        file (func.InputStream): The input binding to read the snippet from Azure Blob Storage.
        context: The trigger context containing the input arguments.

    Returns:
        str: The content of the snippet or an error message.
    """
    if not file:
        return "Snippet not found."

    try:
        snippet_content = file.read().decode("utf-8")
    except Exception as e:
        logging.error("Failed to read snippet: %s", e)
        return "Failed to read snippet."

    logging.info("Retrieved snippet of %d bytes", len(snippet_content))
    return snippet_content


@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="save_snippet",
    description="Save a snippet with a name.",
    toolProperties=tool_properties_save_snippets_json,
)
@app.generic_output_binding(arg_name="file", type="blob", connection="AzureWebJobsStorage", path=_BLOB_PATH)
def save_snippet(file: func.Out[str], context) -> str:
    try:
        content = json.loads(context) if isinstance(context, str) else context
    except Exception as e:
        logging.error("Invalid context JSON: %s", e)
        return "Invalid request: context is not valid JSON."

    if "arguments" not in content or not isinstance(content["arguments"], dict):
        return "No arguments provided"

    snippet_name_from_args = content["arguments"].get(_SNIPPET_NAME_PROPERTY_NAME)
    snippet_content_from_args = content["arguments"].get(_SNIPPET_PROPERTY_NAME)

    if not snippet_name_from_args:
        return "No snippet name provided"

    if not snippet_content_from_args:
        return "No snippet content provided"

    try:
        file.set(snippet_content_from_args)
    except Exception as e:
        logging.error("Failed to save snippet: %s", e)
        return "Failed to save snippet."

    logging.info("Saved snippet of %d bytes", len(snippet_content_from_args))
    return f"Snippet '{snippet_content_from_args}' saved successfully"
