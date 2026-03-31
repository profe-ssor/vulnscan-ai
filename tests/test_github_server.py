"""
Test script for the GitHub MCP Server.

This shows exactly how agents will connect to and call your MCP tools.
The server runs as a subprocess, and the client talks to it over stdio.
"""

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# This tells the client: "launch github_server.py as a subprocess"
SERVER = StdioServerParameters(
    command="uv",
    args=["run", "python", "mcp_servers/github_server.py"],
)

# A small public repo to test with
TEST_REPO = "https://github.com/fastapi/fastapi"


async def main():
    # Connect to the server over stdio
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List available tools — see what the server exposes
            print("=" * 60)
            print("AVAILABLE TOOLS")
            print("=" * 60)
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description[:80]}...")
            print()

            # 2. Clone a repo
            print("=" * 60)
            print(f"CLONING: {TEST_REPO}")
            print("=" * 60)
            result = await session.call_tool("clone_repo", {"repo_url": TEST_REPO})
            repo_path = result.content[0].text
            print(f"  Cloned to: {repo_path}")
            print()

            # 3. Detect languages
            print("=" * 60)
            print("DETECTING LANGUAGES")
            print("=" * 60)
            result = await session.call_tool("detect_languages", {"repo_path": repo_path})
            print(f"  {result.content[0].text}")
            print()

            # 4. List files (first 20)
            print("=" * 60)
            print("LISTING FILES (first 20)")
            print("=" * 60)
            result = await session.call_tool("list_files", {"repo_path": repo_path, "max_files": 20})
            print(f"  {result.content[0].text}")
            print()

            # 5. Read a specific file
            print("=" * 60)
            print("READING: pyproject.toml (first 30 lines)")
            print("=" * 60)
            result = await session.call_tool("read_file", {
                "repo_path": repo_path,
                "file_path": "pyproject.toml",
                "max_lines": 30,
            })
            print(result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
