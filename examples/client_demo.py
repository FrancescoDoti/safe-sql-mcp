import asyncio, sys
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    params = StdioServerParameters(command=sys.executable, args=["-m", "safesql.server", "--db", "data/chinook.sqlite", "--policy", "policy.chinook.json", "--audit", "audit.jsonl"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            print([t.name for t in (await s.list_tools()).tools])
            ok = await s.call_tool("run_query", {"sql": "SELECT Name FROM Genre ORDER BY Name LIMIT 3"})
            print("ok:", ok.is_error, ok.content[0].text[:150])
            bad = await s.call_tool("run_query", {"sql": "SELECT Email FROM Customer"})
            print("bad:", bad.is_error, bad.content[0].text)
asyncio.run(main())
