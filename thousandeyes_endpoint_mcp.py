import os
from typing import List, Dict, Any, Optional
import asyncio
import json
from dotenv import load_dotenv
import httpx
from pydantic import BaseModel
from fastmcp import FastMCP

# Load environment variables
load_dotenv()

# Configuration
API_BASE_URL = os.getenv("THOUSANDEYES_API_BASE_URL", "https://api.thousandeyes.com/v7")
API_TOKEN = os.getenv("THOUSANDEYES_API_TOKEN")
if not API_TOKEN:
    raise ValueError("THOUSANDEYES_API_TOKEN environment variable is required")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/hal+json"
}

# Pydantic models for validation
class EndpointAgent(BaseModel):
    id: str
    name: Optional[str] = None
    computer_name: Optional[str] = None
    os_version: Optional[str] = None
    platform: Optional[str] = None
    status: Optional[str] = None
    last_seen: Optional[str] = None
    number_of_clients: Optional[int] = None

class EndpointAgentUpdate(BaseModel):
    name: Optional[str] = None
    license_type: Optional[str] = None

class ListEndpointAgentsResponse(BaseModel):
    response: List[EndpointAgent]

# Initialize FastMCP server
mcp = FastMCP("thousandeyes_endpoint_mcp")

# Helper for API calls with rate limiting and error handling
async def make_api_request(method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Make an authenticated request to the ThousandEyes Endpoint Agents API.

    Args:
        method: HTTP method (GET, POST, etc.).
        endpoint: API endpoint path (e.g., 'endpoint/agents').
        params: Query parameters (optional).
        data: JSON payload for POST requests (optional).

    Returns:
        API response as dict or error message.
    """
    url = f"{API_BASE_URL}/{endpoint.lstrip('/')}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(method, url, headers=HEADERS, params=params, json=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {"error": "Authentication failed. Check your API token."}
        elif e.response.status_code == 429:
            await asyncio.sleep(1)  # Rate limit delay
            return {"error": "Rate limit exceeded. Please try again later."}
        else:
            return {"error": f"API error: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        print(f"DEBUG: httpx.RequestError encountered: {e}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        print(f"DEBUG: Unexpected error encountered: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def get_endpoint_agents(aid: Optional[str] = None, max_results: Optional[int] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve a list of endpoint agents from ThousandEyes.

    Args:
        aid: Account Group ID (optional).
        max_results: Maximum number of agents to return (optional).
        expand: List of expansions (e.g., ['clients', 'targetVersion']) (optional).

    Returns:
        A JSON-formatted string listing endpoint agents.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if max_results:
        params["max"] = max_results
    if expand:
        params["expand"] = expand

    data = await make_api_request("GET", "endpoint/agents", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    
    agents = [EndpointAgent(**agent).dict() for agent in data.get("response", [])]
    if not agents:
        return json.dumps({"message": "No endpoint agents found."}, indent=2)
    
    return json.dumps(agents, indent=2)

@mcp.tool()
async def get_endpoint_agent(agent_id: str, aid: Optional[str] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve details of a specific endpoint agent.

    Args:
        agent_id: The ID of the endpoint agent.
        aid: Account Group ID (optional).
        expand: List of expansions (e.g., ['clients', 'vpnProfiles']) (optional).

    Returns:
        A JSON-formatted string with endpoint agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if expand:
        params["expand"] = expand

    data = await make_api_request("GET", f"endpoint/agents/{agent_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    
    agent = EndpointAgent(**data).dict()
    return json.dumps(agent, indent=2)

@mcp.tool()
async def update_endpoint_agent(agent_id: str, update_data: EndpointAgentUpdate, aid: Optional[str] = None) -> str:
    """
    Update an endpoint agent.

    Args:
        agent_id: The ID of the endpoint agent.
        update_data: Update parameters (e.g., name, license_type).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated endpoint agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_dict = {k: v for k, v in update_data.dict().items() if v is not None}
    data = await make_api_request("PATCH", f"endpoint/agents/{agent_id}", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    
    agent = EndpointAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_agent": agent
    }, indent=2)

@mcp.tool()
async def delete_endpoint_agent(agent_id: str, aid: Optional[str] = None) -> str:
    """
    Delete an endpoint agent.

    Args:
        agent_id: The ID of the endpoint agent.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string confirming deletion.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("DELETE", f"endpoint/agents/{agent_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    
    return json.dumps({
        "status": "success",
        "message": f"Endpoint agent {agent_id} deleted."
    }, indent=2)

@mcp.resource("greeting: //{name}")
def greeting(name: str) -> str:
    """
    Greet a user by name.

    Args:
        name: The name to include in the greeting.

    Returns:
        A greeting message.
    """
    return f"Hello {name}!"

if __name__ == "__main__":
    mcp.run(transport="stdio")  # Use stdio for Claude Desktop integration
