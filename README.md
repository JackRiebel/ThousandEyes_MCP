# ThousandEyes Endpoint MCP

A Model Context Protocol (MCP) server for Cisco ThousandEyes Endpoint Agents API (v7.0.62). It provides tools for querying, updating, and managing endpoint agents.

**Disclaimer**: For development/POC use. Not intended for production without security hardening.

## Features
- **Endpoint Agent Management**: List, retrieve, update, and delete agents.
- **Account Group Support**: Filter by `aid` (Account Group ID).
- **Expansion Options**: Expand responses with `expand` (e.g., clients, VPN profiles).
- **JSON Responses**: Structured outputs for easy parsing in Claude.

## Installation
1. Clone or create the repo:
   ```
   mkdir ThousandEyes_Endpoint_MCP
   cd ThousandEyes_Endpoint_MCP
   ```
2. Create virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration
1. Copy example env:
   ```
   cp .env-example .env
   ```
2. Update `.env`:
   ```
   THOUSANDEYES_API_BASE_URL=https://api.thousandeyes.com/v7
   THOUSANDEYES_API_TOKEN=your-thousandeyes-api-token-here
   ```
   - Get token from ThousandEyes dashboard: Settings > API Tokens.

## Usage with Claude Desktop
1. Configure Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "thousandeyes_endpoint_mcp": {
         "command": "/path/to/ThousandEyes_Endpoint_MCP/.venv/bin/fastmcp",
         "args": ["run", "/path/to/ThousandEyes_Endpoint_MCP/thousandeyes_endpoint_mcp.py"],
         "cwd": "/path/to/ThousandEyes_Endpoint_MCP",
         "env": {
           "THOUSANDEYES_API_TOKEN": "your-token-here"
         }
       }
     }
   }
   ```
2. Restart Claude Desktop.
3. Prompt examples:
   - "Use thousandeyes_endpoint_mcp to get endpoint agents."
   - "Retrieve details for agent ID abc123 with expand clients."

## Tools
- `get_endpoint_agents(aid?, max_results?, expand?)`: List agents.
- `get_endpoint_agent(agent_id, aid?, expand?)`: Get agent details.
- `update_endpoint_agent(agent_id, update_data, aid?)`: Update agent.
- `delete_endpoint_agent(agent_id, aid?)`: Delete agent.

## Best Practices
- **Rate Limiting**: API limits: 10 req/sec. Code includes delays on 429.
- **Security**: Rotate tokens regularly; use env vars.
- **Validation**: Pydantic schemas ensure data integrity.
- **Troubleshooting**: Check logs for 401 (token), 404 (agent ID), 429 (rate limit).

## About
Based on [Catalyst Center MCP](https://github.com/JackRiebel/Catalyst_Center_MCP). For ThousandEyes Endpoint Agents API v7.0.62.

*Submitted by: [Your Name], Cisco Solutions Engineer | Date: September 22, 2025*
