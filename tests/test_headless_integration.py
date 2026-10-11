"""End-to-end tests against a real headless Ghidra. Skipped unless GHIDRA_INSTALL_DIR is set.

The extension jar is taken from GHIDRA_MCP_EXTENSION_JAR or extension/build/libs/GhidraMCP.jar
(build it with `gradle` in extension/ first).
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests
from mcp.server.fastmcp.exceptions import ToolError

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR")
JAR = Path(os.environ.get("GHIDRA_MCP_EXTENSION_JAR", ROOT / "extension/build/libs/GhidraMCP.jar"))

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.skipif(not GHIDRA, reason="GHIDRA_INSTALL_DIR not set"),
    pytest.mark.skipif(not JAR.is_file(), reason=f"extension jar not built: {JAR}"),
]

BINARIES = {"elf": "sample_x86_64.elf", "pe": "sample_x86_64.exe"}


@pytest.fixture(scope="module", params=sorted(BINARIES))
def headless(request):
    pytest.importorskip("pyghidra")
    from ghidra_mcp.backend import DeferredBackend
    from ghidra_mcp.headless import HeadlessOptions, HeadlessSession
    from ghidra_mcp.server import create_server

    backend = DeferredBackend(5, 120, wait_timeout=1)
    session = HeadlessSession(
        HeadlessOptions(
            binary=FIXTURES / BINARIES[request.param],
            ghidra_install_dir=Path(GHIDRA),
            extension_jar=JAR,
        ),
        backend,
    )
    session.start()
    session.load()
    try:
        yield request.param, backend, create_server(backend, capabilities=set())
    finally:
        session.close()


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


def functions(mcp) -> dict[str, str]:
    page = call(mcp, "list_functions", limit=2000)
    return {f["name"]: f["address"] for f in page["items"]}


def test_program_info(headless):
    kind, _, mcp = headless
    info = call(mcp, "get_program_info")
    assert info["name"] == BINARIES[kind]
    assert info["language_id"] == "x86:LE:64:default"
    expected_format = "Executable and Linking Format (ELF)" if kind == "elf" else "Portable Executable (PE)"
    assert info["executable_format"] == expected_format
    assert info["function_count"] > 0
    assert info["function_count"] == call(mcp, "list_functions", limit=1)["total"]
    imports = call(mcp, "list_imports")["items"]
    assert {i["namespace"] for i in imports if i["namespace"]} <= set(call(mcp, "list_namespaces")["items"])
    assert info["sha256"]


def test_list_functions_pagination_and_filter(headless):
    _, _, mcp = headless
    first = call(mcp, "list_functions", limit=2)
    assert len(first["items"]) == 2 and first["has_more"]
    second = call(mcp, "list_functions", offset=2, limit=2)
    assert first["items"][0] != second["items"][0]
    found = call(mcp, "list_functions", filter="NUMBERS")
    assert {f["name"] for f in found["items"]} >= {"add_numbers", "mul_numbers"}


def test_decompile_by_name_and_address(headless):
    _, _, mcp = headless
    by_name = call(mcp, "decompile_function", name="compute")
    assert "add_numbers" in by_name["code"] and "mul_numbers" in by_name["code"]
    by_addr = call(mcp, "decompile_function_by_address", address=by_name["function"]["address"])
    assert by_addr["function"] == by_name["function"]


def test_disassembly_stays_inside_function_body(headless):
    _, _, mcp = headless
    fns = functions(mcp)
    info = call(mcp, "get_function_by_address", address=fns["add_numbers"])
    lines = call(mcp, "disassemble_function", address=fns["add_numbers"])["items"]
    assert lines
    start, end = int(info["body_start"], 16), int(info["body_end"], 16)
    assert all(start <= int(line["address"], 16) <= end for line in lines)
    assert "RET" in lines[-1]["instruction"]


def test_function_calls(headless):
    _, _, mcp = headless
    fns = functions(mcp)
    calls = call(mcp, "get_function_calls", address=fns["compute"])
    callee_names = {c["name"] for c in calls["callees"]["items"]}
    assert {"add_numbers", "mul_numbers"} <= callee_names
    callers = call(mcp, "get_function_calls", address=fns["add_numbers"], direction="callers")
    assert callers["callees"] is None
    assert "compute" in {c["caller"]["name"] for c in callers["callers"]["items"] if c["caller"]}
    with pytest.raises(ToolError, match="callees"):
        asyncio.run(mcp.call_tool("get_function_calls", {"address": fns["compute"], "direction": "up"}))


def test_strings_and_read_memory(headless):
    _, _, mcp = headless
    strings = call(mcp, "list_strings", filter="fixture-secret")["items"]
    assert strings
    secret = strings[0]
    mem = call(mcp, "read_memory", address=secret["address"], length=9)
    assert mem["ascii"] == "GhidraMCP"
    assert mem["gaps"] == []


def test_read_memory_reports_unmapped_and_limits(headless):
    _, _, mcp = headless
    mem = call(mcp, "read_memory", address="0x0", length=4)
    assert mem["hex"] == "?? ?? ?? ??"
    assert mem["gaps"][0]["reason"] == "unmapped"
    with pytest.raises(ToolError, match="INVALID_PARAMETER"):
        asyncio.run(mcp.call_tool("read_memory", {"address": "0x0", "length": 5000}))


def test_errors_are_tool_errors(headless):
    _, _, mcp = headless
    with pytest.raises(ToolError, match="BAD_ADDRESS"):
        asyncio.run(mcp.call_tool("decompile_function_by_address", {"address": "not-an-address"}))
    with pytest.raises(ToolError, match="FUNCTION_NOT_FOUND"):
        asyncio.run(mcp.call_tool("rename_function", {"old_name": "does_not_exist", "new_name": "x"}))


def test_rename_and_annotate_round_trip(headless):
    _, _, mcp = headless
    fns = functions(mcp)

    renamed = call(mcp, "rename_function_by_address", function_address=fns["mul_numbers"], new_name="multiply")
    assert renamed == {"address": fns["mul_numbers"], "old_name": "mul_numbers", "new_name": "multiply"}
    assert call(mcp, "get_function_by_address", address=fns["mul_numbers"])["name"] == "multiply"
    call(mcp, "rename_function", old_name="multiply", new_name="mul_numbers")

    proto = call(mcp, "set_function_prototype", function_address=fns["add_numbers"],
                 prototype="int add_numbers(int a, int b)")
    assert proto["signature"] == "int add_numbers(int a, int b)"
    proto = call(mcp, "set_function_prototype", function_address=fns["add_numbers"],
                 prototype="int add_ints(int a, int b)")
    assert proto["function"]["name"] == "add_ints"
    call(mcp, "rename_function_by_address", function_address=fns["add_numbers"], new_name="add_numbers")

    var = call(mcp, "rename_variable", function_address=fns["checksum"], old_name="param_1", new_name="buf")
    assert var["new_name"] == "buf"
    typed = call(mcp, "set_local_variable_type", function_address=fns["checksum"],
                 variable_name="buf", new_type="uchar *")
    assert typed["new_type"] == "uchar *"
    assert "uchar *buf" in call(mcp, "decompile_function", name="checksum")["code"]

    comment = call(mcp, "set_disassembly_comment", address=fns["add_numbers"], comment="adds two ints")
    assert comment["comment"] == "adds two ints"
    lines = call(mcp, "disassemble_function", address=fns["add_numbers"])["items"]
    assert lines[0]["comment"] == "adds two ints"
    cleared = call(mcp, "set_disassembly_comment", address=fns["add_numbers"], comment="")
    assert cleared["comment"] is None


def test_unknown_type_is_rejected(headless):
    _, _, mcp = headless
    fns = functions(mcp)
    with pytest.raises(ToolError, match="NOT_FOUND"):
        asyncio.run(mcp.call_tool("set_local_variable_type", {
            "function_address": fns["checksum"], "variable_name": "param_2", "new_type": "NoSuchType_t"}))


def test_backend_rejects_browser_and_rebinding_requests(headless):
    _, backend, _ = headless
    url = backend.base_url + "health"
    with requests.Session() as s:
        s.trust_env = False
        assert s.get(url).json()["data"]["mode"] == "headless"
        assert s.get(url, headers={"Origin": "http://evil.example"}).status_code == 403
        assert s.get(url, headers={"Host": "evil.example"}).status_code == 403
        assert s.get(backend.base_url + "rename_data").status_code == 405
        assert s.get(backend.base_url + "nope").json()["error"]["code"] == "UNKNOWN_ENDPOINT"


@pytest.mark.skipif(sys.platform == "win32", reason="stdio subprocess test uses POSIX paths")
def test_cli_stdio_session():
    """The real `ghidra-mcp --headless` command over MCP stdio, in a separate process."""
    pytest.importorskip("pyghidra")
    script = f"""
import asyncio, json, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "ghidra_mcp", "--headless", "--binary", {str(FIXTURES / BINARIES["elf"])!r},
        "--ghidra-install-dir", {GHIDRA!r}, "--extension-jar", {str(JAR)!r}, "--ready-timeout", "300"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            info = await s.call_tool("get_program_info", {{}})
            print(json.dumps({{"tools": names, "error": info.isError, "info": info.content[0].text}}))

asyncio.run(main())
"""
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stderr[-3000:]
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert "get_current_address" not in result["tools"]
    assert not result["error"], result["info"]
    assert json.loads(result["info"])["name"] == BINARIES["elf"]
