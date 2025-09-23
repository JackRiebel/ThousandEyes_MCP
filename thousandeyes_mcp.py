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

# Pydantic models for Endpoint Agents
class Location(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    locationName: Optional[str] = None

class AsnDetails(BaseModel):
    asNumber: Optional[int] = None
    asName: Optional[str] = None

class Links(BaseModel):
    self: Dict[str, str]

class EndpointAgent(BaseModel):
    id: str
    aid: Optional[str] = None
    name: Optional[str] = None
    computerName: Optional[str] = None
    osVersion: Optional[str] = None
    platform: Optional[str] = None
    kernelVersion: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    status: Optional[str] = None
    lastSeen: Optional[str] = None
    numberOfClients: Optional[int] = None
    publicIP: Optional[str] = None
    version: Optional[str] = None
    deleted: Optional[bool] = None
    createdAt: Optional[str] = None
    location: Optional[Location] = None
    totalMemory: Optional[str] = None
    agentType: Optional[str] = None
    asnDetails: Optional[AsnDetails] = None
    licenseType: Optional[str] = None
    tcpDriverAvailable: Optional[bool] = None
    _links: Optional[Links] = None

    class Config:
        populate_by_name = True

class EndpointAgentUpdate(BaseModel):
    name: Optional[str] = None
    licenseType: Optional[str] = None

class AgentTransferRequest(BaseModel):
    toAid: str

class BulkAgentTransferRequest(BaseModel):
    transfers: List[Dict[str, str]]

# Pydantic models for Cloud and Enterprise Agents
class AgentBase(BaseModel):
    ipAddresses: Optional[List[str]] = None
    publicIpAddresses: Optional[List[str]] = None
    network: Optional[str] = None

class SimpleAgent(AgentBase):
    agentId: str
    agentName: Optional[str] = None
    location: Optional[str] = None
    countryId: Optional[str] = None
    enabled: Optional[bool] = None
    prefix: Optional[str] = None
    verifySslCertificates: Optional[bool] = None

class SimpleTest(BaseModel):
    testId: str
    testName: Optional[str] = None
    type: Optional[str] = None
    interval: Optional[int] = None
    alertsEnabled: Optional[bool] = None
    enabled: Optional[bool] = None
    createdBy: Optional[str] = None
    createdDate: Optional[str] = None
    description: Optional[str] = None
    liveShare: Optional[bool] = None
    modifiedBy: Optional[str] = None
    modifiedDate: Optional[str] = None
    savedEvent: Optional[bool] = None

class AgentLabel(BaseModel):
    labelId: str
    name: Optional[str] = None

class AccountGroup(BaseModel):
    aid: str
    accountGroupName: Optional[str] = None
    builtin: Optional[bool] = None
    hasManagementPermission: Optional[bool] = None

class ErrorDetail(BaseModel):
    code: Optional[str] = None
    description: Optional[str] = None

class InterfaceIpMapping(BaseModel):
    interfaceName: Optional[str] = None
    ipAddresses: Optional[List[str]] = None

class ClusterMember(AgentBase):
    memberId: str
    name: Optional[str] = None
    errorDetails: Optional[List[ErrorDetail]] = None
    lastSeen: Optional[str] = None
    agentState: Optional[str] = None
    targetForTests: Optional[str] = None
    utilization: Optional[int] = None

class EnterpriseAgentData(BaseModel):
    testIds: Optional[List[int]] = None
    tests: Optional[List[SimpleTest]] = None
    clusterMembers: Optional[List[ClusterMember]] = None
    utilization: Optional[int] = None
    accountGroups: Optional[List[AccountGroup]] = None
    ipv6Policy: Optional[str] = None
    errorDetails: Optional[List[ErrorDetail]] = None
    hostname: Optional[str] = None
    lastSeen: Optional[str] = None
    agentState: Optional[str] = None
    keepBrowserCache: Optional[bool] = None
    createdDate: Optional[str] = None
    targetForTests: Optional[str] = None
    localResolutionPrefixes: Optional[List[str]] = None
    interfaceIpMapping: Optional[List[InterfaceIpMapping]] = None

class CloudEnterpriseAgent(SimpleAgent, EnterpriseAgentData):
    agentType: str
    _links: Optional[Links] = None

class AgentRequest(BaseModel):
    agentName: Optional[str] = None
    enabled: Optional[bool] = None
    accountGroups: Optional[List[str]] = None
    tests: Optional[List[str]] = None
    ipv6Policy: Optional[str] = None
    keepBrowserCache: Optional[bool] = None
    targetForTests: Optional[str] = None
    localResolutionPrefixes: Optional[List[str]] = None

class AgentClusterAssignRequest(BaseModel):
    agents: List[str]

class AgentClusterUnassignRequest(BaseModel):
    members: List[str]

class AgentTestsAssignRequest(BaseModel):
    testIds: List[str]

class NotificationRule(BaseModel):
    ruleId: str
    ruleName: Optional[str] = None
    expression: Optional[str] = None
    notifyOnClear: Optional[bool] = None
    isDefault: Optional[bool] = None

class AgentNotification(BaseModel):
    email: Optional[Dict[str, Any]] = None
    thirdParty: Optional[List[Dict[str, Any]]] = None
    webhook: Optional[List[Dict[str, Any]]] = None

class NotificationRuleDetail(NotificationRule):
    notifications: Optional[AgentNotification] = None
    agents: Optional[List[CloudEnterpriseAgent]] = None
    _links: Optional[Links] = None

class AgentProxy(BaseModel):
    aid: Optional[str] = None
    authType: Optional[str] = None
    bypassList: Optional[List[str]] = None
    lastModified: Optional[str] = None
    location: Optional[str] = None
    isLocalConfigured: Optional[bool] = None
    name: Optional[str] = None
    password: Optional[str] = None
    proxyId: Optional[str] = None
    type: Optional[str] = None
    user: Optional[str] = None

# Pydantic models for Administrative API
class User(BaseModel):
    name: Optional[str] = None
    email: str
    uid: Optional[str] = None
    dateRegistered: Optional[str] = None

class ExtendedUser(User):
    lastLogin: Optional[str] = None

class AccountGroupRole(BaseModel):
    aid: str
    roleId: str
    roleName: Optional[str] = None

class UserAccountGroupRole(BaseModel):
    aid: str
    roleIds: List[str]

class UserDetail(ExtendedUser):
    loginAccountGroup: Optional[AccountGroup] = None
    accountGroupRoles: Optional[List[AccountGroupRole]] = None
    allAccountGroupRoles: Optional[List[Dict[str, Any]]] = None
    _links: Optional[Links] = None

class UserRequest(BaseModel):
    name: Optional[str] = None
    email: str
    loginAccountGroupId: Optional[str] = None
    accountGroupRoles: Optional[List[UserAccountGroupRole]] = None
    allAccountGroupRoleIds: Optional[List[str]] = None

class CreatedUser(User):
    loginAccountGroup: Optional[AccountGroup] = None
    accountGroupRoles: Optional[List[AccountGroupRole]] = None
    allAccountGroupRoles: Optional[List[Dict[str, Any]]] = None
    _links: Optional[Links] = None

class Role(BaseModel):
    name: str
    roleId: str
    isBuiltin: Optional[bool] = None
    hasManagementPermissions: Optional[bool] = None

class RoleDetail(Role):
    permissions: Optional[List[Dict[str, Any]]] = None
    _links: Optional[Links] = None

class RoleRequestBody(BaseModel):
    name: str
    permissions: Optional[List[str]] = None

class Permission(BaseModel):
    label: Optional[str] = None
    permissionId: str
    isManagementPermission: Optional[bool] = None
    permission: Optional[str] = None

class UserEvent(BaseModel):
    aid: Optional[str] = None
    accountGroupName: Optional[str] = None
    date: Optional[str] = None
    event: Optional[str] = None
    ipAddress: Optional[str] = None
    uid: Optional[str] = None
    user: Optional[str] = None
    resources: Optional[List[Dict[str, str]]] = None

class AuditUserEvents(BaseModel):
    auditEvents: Optional[List[UserEvent]] = None
    startDate: Optional[str] = None
    endDate: Optional[str] = None
    _links: Optional[Dict[str, Any]] = None

class AccountGroupRequest(BaseModel):
    accountGroupName: str
    agents: Optional[List[str]] = None

class CreatedAccountGroup(AccountGroup):
    _links: Optional[Links] = None

class AccountGroupDetail(AccountGroup):
    users: Optional[List[Dict[str, Any]]] = None
    _links: Optional[Links] = None

# Initialize FastMCP server
mcp = FastMCP("thousandeyes_endpoint_mcp")

# Helper for API calls with rate limiting and error handling
async def make_api_request(method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Make an authenticated request to the ThousandEyes API with SSL verification disabled.

    Args:
        method: HTTP method (GET, POST, DELETE, PUT, PATCH).
        endpoint: API endpoint path (e.g., 'endpoint/agents').
        params: Query parameters (optional).
        data: JSON payload for POST/PUT/PATCH requests (optional).

    Returns:
        Dict containing the API response or an error message.
    """
    url = f"{API_BASE_URL}/{endpoint.lstrip('/')}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
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

# Endpoint Agent Functions
@mcp.tool()
async def get_endpoint_agents(aid: Optional[str] = None, max_results: Optional[int] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve a list of endpoint agents from ThousandEyes.

    Args:
        aid: Account Group ID (optional).
        max_results: Maximum number of agents to return (optional).
        expand: List of expansions (e.g., ['clients', 'targetVersion']) (optional).

    Returns:
        A JSON-formatted string listing endpoint agents with ID, name, and other details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if max_results:
        params["max"] = max_results
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("GET", "endpoint/agents", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agents = [EndpointAgent(**agent).dict() for agent in data.get("agents", [])]
    if not agents:
        return json.dumps({"message": "No endpoint agents found."}, indent=2)

    return json.dumps(agents, indent=2)

@mcp.tool()
async def get_endpoint_agent(agent_id: str, aid: Optional[str] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve details of a specific endpoint agent.

    Args:
        agent_id: The ID of the agent to retrieve.
        aid: Account Group ID (optional).
        expand: List of expansions (e.g., ['clients', 'targetVersion']) (optional).

    Returns:
        A JSON-formatted string with agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("GET", f"endpoint/agents/{agent_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = EndpointAgent(**data).dict()
    return json.dumps(agent, indent=2)

@mcp.tool()
async def update_endpoint_agent(agent_id: str, update_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Update an endpoint agent with the specified fields (name, license_type).

    Args:
        agent_id: The ID of the agent to update.
        update_data: Dictionary with fields to update (e.g., {'name': 'NewName', 'license_type': 'essentials'}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = EndpointAgentUpdate(**update_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
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
        agent_id: The ID of the agent to delete.
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

@mcp.tool()
async def enable_endpoint_agent(agent_id: str, aid: Optional[str] = None) -> str:
    """
    Enable an endpoint agent.

    Args:
        agent_id: The ID of the agent to enable.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with enabled agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("POST", f"endpoint/agents/{agent_id}/enable", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = EndpointAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "enabled_agent": agent
    }, indent=2)

@mcp.tool()
async def disable_endpoint_agent(agent_id: str, aid: Optional[str] = None) -> str:
    """
    Disable an endpoint agent.

    Args:
        agent_id: The ID of the agent to disable.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with disabled agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("POST", f"endpoint/agents/{agent_id}/disable", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = EndpointAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "disabled_agent": agent
    }, indent=2)

@mcp.tool()
async def filter_endpoint_agents(search_filters: Dict[str, Any], aid: Optional[str] = None, max_results: Optional[int] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve a list of endpoint agents matching the specified filters.

    Args:
        search_filters: Dictionary of filter criteria (e.g., {'agentName': ['myagent-1234']}).
        aid: Account Group ID (optional).
        max_results: Maximum number of agents to return (optional).
        expand: List of expansions (e.g., ['clients', 'targetVersion']) (optional).

    Returns:
        A JSON-formatted string listing filtered agents.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if max_results:
        params["max"] = max_results
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("POST", "endpoint/agents/filter", params=params, data={"searchFilters": search_filters})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agents = [EndpointAgent(**agent).dict() for agent in data.get("agents", [])]
    if not agents:
        return json.dumps({"message": "No endpoint agents found matching the filters."}, indent=2)

    return json.dumps(agents, indent=2)

@mcp.tool()
async def get_endpoint_agents_connection_string(aid: Optional[str] = None) -> str:
    """
    Retrieve the connection string for endpoint agents.

    Args:
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with connection string.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", "endpoint/agents/connection-string", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps(data, indent=2)

@mcp.tool()
async def transfer_endpoint_agent(agent_id: str, to_aid: str, aid: Optional[str] = None) -> str:
    """
    Initiate transfer of an endpoint agent to another account.

    Args:
        agent_id: The ID of the agent to transfer.
        to_aid: The target Account Group ID.
        aid: Source Account Group ID (optional).

    Returns:
        A JSON-formatted string confirming transfer initiation.
    """
    params = {}
    if aid:
        params["aid"] = aid

    request_data = AgentTransferRequest(toAid=to_aid).dict()
    data = await make_api_request("POST", f"endpoint/agents/{agent_id}/transfer", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps({
        "status": "success",
        "message": f"Transfer initiated for agent {agent_id} to account {to_aid}."
    }, indent=2)

@mcp.tool()
async def bulk_transfer_endpoint_agents(transfers: List[Dict[str, str]], aid: Optional[str] = None) -> str:
    """
    Initiate bulk transfer of multiple endpoint agents to other accounts.

    Args:
        transfers: List of dictionaries with agent_id, fromAid, and toAid.
        aid: Source Account Group ID (optional).

    Returns:
        A JSON-formatted string with transfer statuses.
    """
    params = {}
    if aid:
        params["aid"] = aid

    request_data = BulkAgentTransferRequest(transfers=transfers).dict()
    data = await make_api_request("POST", "endpoint/agents/transfer/bulk", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps(data, indent=2)

# Cloud and Enterprise Agent Functions
@mcp.tool()
async def get_agents(aid: Optional[str] = None, agent_types: Optional[List[str]] = None, labels: Optional[List[str]] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve a list of Cloud and Enterprise Agents from ThousandEyes.

    Args:
        aid: Account Group ID (optional).
        agent_types: List of agent types to filter (e.g., ['enterprise', 'cloud']) (optional).
        labels: List of agent labels to filter (e.g., ['myCustomLabeledAgent']) (optional).
        expand: List of expansions (e.g., ['cluster-member', 'test']) (optional).

    Returns:
        A JSON-formatted string listing Cloud and Enterprise Agents with details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if agent_types:
        params["agentTypes"] = ",".join(agent_types)
    if labels:
        params["labels"] = ",".join(labels)
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("GET", "agents", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agents = [CloudEnterpriseAgent(**agent).dict() for agent in data.get("agents", [])]
    if not agents:
        return json.dumps({"message": "No agents found."}, indent=2)

    return json.dumps(agents, indent=2)

@mcp.tool()
async def get_agent(agent_id: str, aid: Optional[str] = None, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve details of a specific Cloud or Enterprise Agent.

    Args:
        agent_id: The ID of the agent to retrieve.
        aid: Account Group ID (optional).
        expand: List of expansions (e.g., ['cluster-member', 'test']) (optional).

    Returns:
        A JSON-formatted string with agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("GET", f"agents/{agent_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps(agent, indent=2)

@mcp.tool()
async def delete_agent(agent_id: str, aid: Optional[str] = None) -> str:
    """
    Delete an Enterprise Agent.

    Args:
        agent_id: The ID of the agent to delete.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string confirming deletion.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("DELETE", f"agents/{agent_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps({
        "status": "success",
        "message": f"Agent {agent_id} deleted."
    }, indent=2)

@mcp.tool()
async def update_agent(agent_id: str, update_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Update an Enterprise Agent with the specified fields.

    Args:
        agent_id: The ID of the agent to update.
        update_data: Dictionary with fields to update (e.g., {'agentName': 'NewName', 'enabled': True}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = AgentRequest(**update_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("PUT", f"agents/{agent_id}", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_agent": agent
    }, indent=2)

@mcp.tool()
async def assign_agent_to_cluster(agent_id: str, agents: List[str], aid: Optional[str] = None, expand: Optional[List[str]] = None) -> str:
    """
    Assign agents to an Enterprise Agent cluster.

    Args:
        agent_id: The ID of the agent to create or update the cluster.
        agents: List of agent IDs to add to the cluster.
        aid: Account Group ID (optional).
        expand: List of expansions (e.g., ['cluster-member']) (optional).

    Returns:
        A JSON-formatted string with cluster details.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if expand:
        params["expand"] = ",".join(expand)

    request_data = AgentClusterAssignRequest(agents=agents).dict()
    data = await make_api_request("POST", f"agents/{agent_id}/cluster/assign", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "cluster": agent
    }, indent=2)

@mcp.tool()
async def unassign_agent_from_cluster(agent_id: str, members: List[str], aid: Optional[str] = None, expand: Optional[List[str]] = None) -> str:
    """
    Remove members from an Enterprise Agent cluster or convert it to a standalone agent.

    Args:
        agent_id: The ID of the cluster to modify.
        members: List of member IDs to remove from the cluster.
        aid: Account Group ID (optional).
        expand: List of expansions (e.g., ['cluster-member']) (optional).

    Returns:
        A JSON-formatted string with updated agents list.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if expand:
        params["expand"] = ",".join(expand)

    request_data = AgentClusterUnassignRequest(members=members).dict()
    data = await make_api_request("POST", f"agents/{agent_id}/cluster/unassign", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agents = [CloudEnterpriseAgent(**agent).dict() for agent in data.get("agents", [])]
    return json.dumps({
        "status": "success",
        "agents": agents
    }, indent=2)

@mcp.tool()
async def get_agents_notification_rules(aid: Optional[str] = None) -> str:
    """
    Retrieve a list of agent notification rules.

    Args:
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string listing notification rules.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", "agents/notification-rules", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    rules = [NotificationRule(**rule).dict() for rule in data.get("agentAlertRules", [])]
    if not rules:
        return json.dumps({"message": "No notification rules found."}, indent=2)

    return json.dumps(rules, indent=2)

@mcp.tool()
async def get_agents_notification_rule(notification_rule_id: str, aid: Optional[str] = None) -> str:
    """
    Retrieve details of a specific agent notification rule.

    Args:
        notification_rule_id: The ID of the notification rule to retrieve.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with notification rule details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", f"agents/notification-rules/{notification_rule_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    rule = NotificationRuleDetail(**data).dict()
    return json.dumps(rule, indent=2)

@mcp.tool()
async def get_agents_proxies(aid: Optional[str] = None) -> str:
    """
    Retrieve a list of enterprise agent proxies.

    Args:
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string listing agent proxies.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", "agents/proxies", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    proxies = [AgentProxy(**proxy).dict() for proxy in data.get("agentProxies", [])]
    if not proxies:
        return json.dumps({"message": "No agent proxies found."}, indent=2)

    return json.dumps(proxies, indent=2)

@mcp.tool()
async def assign_tests(agent_id: str, test_ids: List[str], aid: Optional[str] = None) -> str:
    """
    Assign tests to a specific Enterprise Agent.

    Args:
        agent_id: The ID of the agent to assign tests to.
        test_ids: List of test IDs to assign.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    request_data = AgentTestsAssignRequest(testIds=test_ids).dict()
    data = await make_api_request("POST", f"agents/{agent_id}/tests/assign", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_agent": agent
    }, indent=2)

@mcp.tool()
async def overwrite_tests(agent_id: str, test_ids: List[str], aid: Optional[str] = None) -> str:
    """
    Replace all tests assigned to a specific Enterprise Agent with a new set.

    Args:
        agent_id: The ID of the agent to overwrite tests for.
        test_ids: List of test IDs to assign.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    request_data = AgentTestsAssignRequest(testIds=test_ids).dict()
    data = await make_api_request("POST", f"agents/{agent_id}/tests/override", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_agent": agent
    }, indent=2)

@mcp.tool()
async def unassign_tests(agent_id: str, test_ids: List[str], aid: Optional[str] = None) -> str:
    """
    Unassign tests from a specific Enterprise Agent.

    Args:
        agent_id: The ID of the agent to unassign tests from.
        test_ids: List of test IDs to unassign.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated agent details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    request_data = AgentTestsAssignRequest(testIds=test_ids).dict()
    data = await make_api_request("POST", f"agents/{agent_id}/tests/unassign", params=params, data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    agent = CloudEnterpriseAgent(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_agent": agent
    }, indent=2)

# Administrative API Functions
@mcp.tool()
async def get_account_groups() -> str:
    """
    Retrieve a list of account groups available to the current user.

    Returns:
        A JSON-formatted string listing account groups.
    """
    data = await make_api_request("GET", "account-groups")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    account_groups = [AccountGroup(**ag).dict() for ag in data.get("accountGroups", [])]
    if not account_groups:
        return json.dumps({"message": "No account groups found."}, indent=2)

    return json.dumps(account_groups, indent=2)

@mcp.tool()
async def create_account_group(account_group_data: Dict[str, Any], expand: Optional[List[str]] = None) -> str:
    """
    Create a new account group.

    Args:
        account_group_data: Dictionary with account group details (e.g., {'accountGroupName': 'New Group', 'agents': ['agentId1']})
        expand: List of expansions (e.g., ['user']) (optional).

    Returns:
        A JSON-formatted string with created account group details.
    """
    params = {}
    if expand:
        params["expand"] = ",".join(expand)

    update_model = AccountGroupRequest(**account_group_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("POST", "account-groups", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    account_group = CreatedAccountGroup(**data).dict()
    return json.dumps({
        "status": "success",
        "created_account_group": account_group
    }, indent=2)

@mcp.tool()
async def get_account_group(account_group_id: str, expand: Optional[List[str]] = None) -> str:
    """
    Retrieve detailed information about an account group.

    Args:
        account_group_id: The ID of the account group to retrieve.
        expand: List of expansions (e.g., ['user']) (optional).

    Returns:
        A JSON-formatted string with account group details.
    """
    params = {}
    if expand:
        params["expand"] = ",".join(expand)

    data = await make_api_request("GET", f"account-groups/{account_group_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    account_group = AccountGroupDetail(**data).dict()
    return json.dumps(account_group, indent=2)

@mcp.tool()
async def update_account_group(account_group_id: str, update_data: Dict[str, Any], expand: Optional[List[str]] = None) -> str:
    """
    Update an account group.

    Args:
        account_group_id: The ID of the account group to update.
        update_data: Dictionary with fields to update (e.g., {'accountGroupName': 'Updated Name'}).
        expand: List of expansions (e.g., ['user']) (optional).

    Returns:
        A JSON-formatted string with updated account group details.
    """
    params = {}
    if expand:
        params["expand"] = ",".join(expand)

    update_model = AccountGroupRequest(**update_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("PUT", f"account-groups/{account_group_id}", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    account_group = AccountGroupDetail(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_account_group": account_group
    }, indent=2)

@mcp.tool()
async def delete_account_group(account_group_id: str) -> str:
    """
    Delete an account group.

    Args:
        account_group_id: The ID of the account group to delete.

    Returns:
        A JSON-formatted string confirming deletion.
    """
    data = await make_api_request("DELETE", f"account-groups/{account_group_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps({
        "status": "success",
        "message": f"Account group {account_group_id} deleted."
    }, indent=2)

@mcp.tool()
async def get_users(aid: Optional[str] = None) -> str:
    """
    Retrieve a list of users in the organization.

    Args:
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string listing users.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", "users", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    users = [ExtendedUser(**user).dict() for user in data.get("users", [])]
    if not users:
        return json.dumps({"message": "No users found."}, indent=2)

    return json.dumps(users, indent=2)

@mcp.tool()
async def create_user(user_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Create a new user.

    Args:
        user_data: Dictionary with user details (e.g., {'name': 'New User', 'email': 'user@example.com'}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with created user details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = UserRequest(**user_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("POST", "users", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    user = CreatedUser(**data).dict()
    return json.dumps({
        "status": "success",
        "created_user": user
    }, indent=2)

@mcp.tool()
async def get_user(user_id: str, aid: Optional[str] = None) -> str:
    """
    Retrieve detailed information about a user.

    Args:
        user_id: The ID of the user to retrieve.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with user details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", f"users/{user_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    user = UserDetail(**data).dict()
    return json.dumps(user, indent=2)

@mcp.tool()
async def update_user(user_id: str, update_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Update a user.

    Args:
        user_id: The ID of the user to update.
        update_data: Dictionary with fields to update (e.g., {'name': 'Updated Name'}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated user details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = UserRequest(**update_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("PUT", f"users/{user_id}", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    user = UserDetail(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_user": user
    }, indent=2)

@mcp.tool()
async def delete_user(user_id: str, aid: Optional[str] = None) -> str:
    """
    Delete a user.

    Args:
        user_id: The ID of the user to delete.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string confirming deletion.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("DELETE", f"users/{user_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps({
        "status": "success",
        "message": f"User {user_id} deleted."
    }, indent=2)

@mcp.tool()
async def get_roles(aid: Optional[str] = None) -> str:
    """
    Retrieve a list of roles.

    Args:
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string listing roles.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", "roles", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    roles = [Role(**role).dict() for role in data.get("roles", [])]
    if not roles:
        return json.dumps({"message": "No roles found."}, indent=2)

    return json.dumps(roles, indent=2)

@mcp.tool()
async def create_role(role_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Create a new role.

    Args:
        role_data: Dictionary with role details (e.g., {'name': 'New Role', 'permissions': ['perm1']}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with created role details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = RoleRequestBody(**role_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("POST", "roles", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    role = RoleDetail(**data).dict()
    return json.dumps({
        "status": "success",
        "created_role": role
    }, indent=2)

@mcp.tool()
async def get_role(role_id: str, aid: Optional[str] = None) -> str:
    """
    Retrieve detailed information about a role.

    Args:
        role_id: The ID of the role to retrieve.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with role details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("GET", f"roles/{role_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    role = RoleDetail(**data).dict()
    return json.dumps(role, indent=2)

@mcp.tool()
async def update_role(role_id: str, update_data: Dict[str, Any], aid: Optional[str] = None) -> str:
    """
    Update a role.

    Args:
        role_id: The ID of the role to update.
        update_data: Dictionary with fields to update (e.g., {'name': 'Updated Role'}).
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string with updated role details.
    """
    params = {}
    if aid:
        params["aid"] = aid

    update_model = RoleRequestBody(**update_data)
    update_dict = {k: v for k, v in update_model.dict().items() if v is not None}
    data = await make_api_request("PUT", f"roles/{role_id}", params=params, data=update_dict)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    role = RoleDetail(**data).dict()
    return json.dumps({
        "status": "success",
        "updated_role": role
    }, indent=2)

@mcp.tool()
async def delete_role(role_id: str, aid: Optional[str] = None) -> str:
    """
    Delete a role.

    Args:
        role_id: The ID of the role to delete.
        aid: Account Group ID (optional).

    Returns:
        A JSON-formatted string confirming deletion.
    """
    params = {}
    if aid:
        params["aid"] = aid

    data = await make_api_request("DELETE", f"roles/{role_id}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    return json.dumps({
        "status": "success",
        "message": f"Role {role_id} deleted."
    }, indent=2)

@mcp.tool()
async def get_permissions() -> str:
    """
    Retrieve all assignable permissions.

    Returns:
        A JSON-formatted string listing permissions.
    """
    data = await make_api_request("GET", "permissions")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    permissions = [Permission(**perm).dict() for perm in data.get("permissions", [])]
    if not permissions:
        return json.dumps({"message": "No permissions found."}, indent=2)

    return json.dumps(permissions, indent=2)

@mcp.tool()
async def get_audit_user_events(aid: Optional[str] = None, window: Optional[int] = None, from_date: Optional[str] = None, to_date: Optional[str] = None) -> str:
    """
    Retrieve all activity log events.

    Args:
        aid: Account Group ID (optional).
        window: Time window in hours (optional).
        from_date: Start date for events (ISO format, optional).
        to_date: End date for events (ISO format, optional).

    Returns:
        A JSON-formatted string with user events.
    """
    params = {}
    if aid:
        params["aid"] = aid
    if window:
        params["window"] = window
    if from_date:
        params["from"] = from_date
    if to_date:
        params["to"] = to_date

    data = await make_api_request("GET", "audit-user-events", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)

    events = AuditUserEvents(**data).dict()
    return json.dumps(events, indent=2)

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
