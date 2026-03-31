"""
Test script for the CVE/NVD MCP Server.
Queries real vulnerability data from the National Vulnerability Database.
"""

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = StdioServerParameters(
    command="uv",
    args=["run", "python", "mcp_servers/cve_server.py"],
)


async def main():
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            print("=" * 60)
            print("AVAILABLE TOOLS")
            print("=" * 60)
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"  - {tool.name}")
            print()

            # 2. Search for CVEs affecting "requests" (Python HTTP library)
            print("=" * 60)
            print("SEARCHING: requests (Python)")
            print("=" * 60)
            result = await session.call_tool("search_cves", {
                "package_name": "requests",
                "version": "2.25.0",
                "max_results": 3,
            })
            print(result.content[0].text)
            print()

            # 3. Get details on a specific well-known CVE (Log4Shell)
            print("=" * 60)
            print("LOOKUP: CVE-2021-44228 (Log4Shell)")
            print("=" * 60)
            result = await session.call_tool("get_cve_details", {
                "cve_id": "CVE-2021-44228",
            })
            print(result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
