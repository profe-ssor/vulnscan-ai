"""
Test script for the OWASP Patterns MCP Server.
Feeds it intentionally vulnerable code and checks what it catches.
"""

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = StdioServerParameters(
    command="uv",
    args=["run", "python", "mcp_servers/owasp_server.py"],
)

# Intentionally vulnerable Python code for testing
VULNERABLE_CODE = '''
import os
import pickle
import hashlib
import requests

DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    os.system(f"echo {user_input}")

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

def check_score(expr):
    return eval(expr)

def login(username, password):
    print(f"Login attempt with password: {password}")

def fetch_data():
    resp = requests.get("http://api.example.com/data", verify=False)
    return resp.json()

app.debug = True
DEBUG = True
'''


async def main():
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List all patterns
            print("=" * 60)
            print("AVAILABLE PATTERNS")
            print("=" * 60)
            result = await session.call_tool("list_patterns", {})
            for block in result.content:
                print(block.text)
            print()

            # 2. Scan the vulnerable code
            print("=" * 60)
            print(f"SCANNING VULNERABLE CODE — {len(VULNERABLE_CODE.splitlines())} lines")
            print("=" * 60)
            result = await session.call_tool("scan_code", {
                "file_path": "app.py",
                "content": VULNERABLE_CODE,
            })
            for block in result.content:
                print(block.text)
                print("-" * 40)


if __name__ == "__main__":
    asyncio.run(main())
