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


def tool_error(mcp, tool, code, **args):
    with pytest.raises(ToolError, match=code):
        asyncio.run(mcp.call_tool(tool, args))


def fields(info) -> dict[str, dict]:
    return {f["name"]: f for f in info["fields"]}


def test_define_c_types(headless):
    _, _, mcp = headless
    source = """
        struct mcp_node { int value; struct mcp_node *next; };
        typedef struct mcp_node mcp_node_t;
        enum mcp_color { MCP_RED, MCP_GREEN = 5 };
    """
    defined = call(mcp, "define_c_types", source=source)
    assert {t["path"] for t in defined["created"]} >= {
        "/ghidra-mcp/mcp_node", "/ghidra-mcp/mcp_node_t", "/ghidra-mcp/mcp_color"}

    node = call(mcp, "get_data_type", name="mcp_node")
    assert node["kind"] == "struct" and node["size"] == 16
    assert fields(node)["next"]["type"] == "mcp_node *" and fields(node)["next"]["offset"] == 8
    assert "struct mcp_node" in node["c_declaration"]
    assert call(mcp, "get_data_type", name="/ghidra-mcp/mcp_node_t")["base_type"] == "mcp_node"
    color = call(mcp, "get_data_type", name="enum mcp_color")
    assert [(v["name"], v["value"]) for v in color["values"]] == [("MCP_RED", 0), ("MCP_GREEN", 5)]

    listed = call(mcp, "list_data_types", category="/ghidra-mcp", kind="struct")["items"]
    assert "/ghidra-mcp/mcp_node" in {t["path"] for t in listed}
    assert all(t["path"].startswith("/ghidra-mcp/") and t["kind"] == "struct" for t in listed)
    everything = call(mcp, "list_data_types", category="/ghidra-mcp", limit=2000)["items"]
    assert all(t["path"].startswith("/ghidra-mcp/") for t in everything)

    # Anonymous structs nested in a union go into the category with everything else.
    def user_types():
        return {t["path"] for t in call(mcp, "list_data_types", limit=2000)["items"]
                if t["kind"] != "builtin"}

    before = user_types()
    anon = call(mcp, "define_c_types", category="/mcp_anon", source="""
        union mcp_payload { struct { int seq; int ts; } ping; struct { short op; short arg; } ctrl; };
    """)
    assert all(t["path"].startswith("/mcp_anon/") for t in anon["created"])
    assert len(anon["created"]) == 3
    added = user_types() - before
    assert added == {t["path"] for t in anon["created"]}
    payload = call(mcp, "get_data_type", name="mcp_payload")
    assert all(f["type"].startswith("_struct_") for f in payload["fields"])

    # Tag references to existing types reuse them rather than creating empty placeholders.
    wrap = call(mcp, "define_c_types", source="struct mcp_wrap { mcp_node_t inner; struct mcp_node *p; };")
    assert [t["name"] for t in wrap["created"]] == ["mcp_wrap"]
    assert "/mcp_node" not in user_types()
    assert fields(call(mcp, "get_data_type", name="mcp_wrap"))["inner"]["type"] == "mcp_node_t"


def test_define_c_types_conflicts(headless):
    _, _, mcp = headless
    call(mcp, "define_c_types", source="struct mcp_dup { int a; };")
    tool_error(mcp, "define_c_types", "NAME_CONFLICT", source="struct mcp_dup { char b; };")
    kept = call(mcp, "define_c_types", source="struct mcp_dup { char b; };", on_conflict="keep")
    assert kept["kept"][0]["size"] == 4
    replaced = call(mcp, "define_c_types", source="struct mcp_dup { long long c; };",
                    on_conflict="replace")
    assert replaced["replaced"][0]["size"] == 8
    names = {t["name"] for t in call(mcp, "list_data_types", filter="mcp_dup")["items"]}
    assert names == {"mcp_dup"}


def test_define_c_types_rejects_bad_source(headless):
    _, _, mcp = headless
    tool_error(mcp, "define_c_types", "preprocessor", source="#include <stdint.h>\nstruct a { int x; };")
    tool_error(mcp, "define_c_types", "Could not parse", source="struct mcp_broken { int a ")
    tool_error(mcp, "define_c_types", "MISSING_PARAMETER", source="")


def test_struct_editing(headless):
    _, _, mcp = headless
    created = call(mcp, "create_struct", name="mcp_hdr", size=16, fields=[
        {"type": "uint", "name": "magic", "offset": 0},
        {"type": "mcp_hdr *", "name": "self", "offset": 8},
    ])
    assert created["action"] == "created"
    hdr = created["data_type"]
    assert hdr["size"] == 16 and not hdr["packing_enabled"]
    assert fields(hdr)["self"]["type"] == "mcp_hdr *"

    hdr = call(mcp, "add_struct_field", name="mcp_hdr",
               field={"type": "ushort", "name": "flags", "offset": 4})
    assert fields(hdr)["flags"]["offset"] == 4
    hdr = call(mcp, "add_struct_field", name="mcp_hdr", field={"type": "int", "name": "tail", "offset": 16})
    assert hdr["size"] == 20
    tool_error(mcp, "add_struct_field", "INVALID_PARAMETER", name="mcp_hdr",
               field={"type": "int", "offset": 2})

    hdr = call(mcp, "update_struct_field", name="mcp_hdr", offset=4, new_name="flag_bits", comment="bits")
    assert fields(hdr)["flag_bits"]["comment"] == "bits"
    hdr = call(mcp, "update_struct_field", name="mcp_hdr", field_name="flag_bits", new_type="uint")
    assert fields(hdr)["flag_bits"]["length"] == 4 and fields(hdr)["flag_bits"]["comment"] == "bits"
    tool_error(mcp, "update_struct_field", "NOT_FOUND", name="mcp_hdr", field_name="nope", new_name="x")

    hdr = call(mcp, "delete_struct_field", name="mcp_hdr", offset=16)
    assert "tail" not in fields(hdr) and hdr["size"] == 20

    packed = call(mcp, "create_struct", name="mcp_packed", packing_enabled=True, fields=[
        {"type": "char", "name": "a"}, {"type": "int", "name": "b"},
        {"type": "uint", "name": "lo", "bit_size": 3}, {"type": "uint", "name": "hi", "bit_size": 5},
    ])["data_type"]
    assert fields(packed)["b"]["offset"] == 4
    assert fields(packed)["hi"]["bit_size"] == 5
    tool_error(mcp, "create_struct", "INVALID_PARAMETER", name="mcp_packed2", packing_enabled=True,
               fields=[{"type": "int", "offset": 4}])
    tool_error(mcp, "create_struct", "NOT_FOUND", name="mcp_bad", fields=[{"type": "NoSuchType_t"}])
    tool_error(mcp, "get_data_type", "NOT_FOUND", name="mcp_bad")


def test_enum_typedef_union_and_function_definition(headless):
    _, _, mcp = headless
    mode = call(mcp, "create_enum", name="mcp_mode", values={"A": 0, "B": 2}, size=1)["data_type"]
    assert mode["size"] == 1
    mode = call(mcp, "set_enum_value", name="mcp_mode", value_name="C", value=7)
    mode = call(mcp, "delete_enum_value", name="mcp_mode", value_name="A")
    assert [(v["name"], v["value"]) for v in mode["values"]] == [("B", 2), ("C", 7)]
    tool_error(mcp, "create_enum", "INVALID_PARAMETER", name="mcp_big", values={"X": 300}, size=1)

    handle = call(mcp, "create_typedef", name="mcp_handle", base_type="void *")["data_type"]
    assert handle["kind"] == "typedef" and handle["base_type"] == "void *"
    tool_error(mcp, "create_typedef", "NOT_FOUND", name="mcp_missing", base_type="NoSuchType_t")

    u = call(mcp, "create_union", name="mcp_u", fields=[{"type": "int", "name": "i"},
                                                       {"type": "double", "name": "d"}])["data_type"]
    assert u["kind"] == "union" and u["size"] == 8

    cb = call(mcp, "create_function_definition", prototype="int mcp_cb(void *ctx, int n)")["data_type"]
    assert cb["kind"] == "function" and "mcp_cb" in cb["prototype"]
    namer = call(mcp, "create_function_definition", prototype="char **mcp_namer(int id)")["data_type"]
    assert namer["name"] == "mcp_namer" and namer["prototype"].startswith("char * *")
    ops = call(mcp, "create_struct", name="mcp_ops", fields=[{"type": "mcp_cb *", "name": "cb"}])
    assert ops["data_type"]["size"] == 8
    tool_error(mcp, "create_struct", "INVALID_PARAMETER", name="mcp_ops2", fields=[{"type": "mcp_cb"}])


def test_apply_and_use_types(headless):
    _, _, mcp = headless
    call(mcp, "define_c_types", source="struct mcp_secret { char text[9]; char rest[16]; };")
    secret = call(mcp, "list_strings", filter="fixture-secret")["items"][0]["address"]
    tool_error(mcp, "apply_data_type", "clear_existing", address=secret, type="mcp_secret")
    applied = call(mcp, "apply_data_type", address=secret, type="mcp_secret", clear_existing=True)
    assert applied["type"] == "mcp_secret" and applied["length"] == 25
    data = {d["address"]: d for d in call(mcp, "list_data_items", limit=2000)["items"]}
    assert data[applied["address"]]["type"] == "mcp_secret"

    fns = functions(mcp)
    proto = call(mcp, "set_function_prototype", function_address=fns["checksum"],
                 prototype="uint checksum(struct mcp_secret *s, uint len)")
    assert "mcp_secret *" in proto["signature"]
    assert "mcp_secret *s" in call(mcp, "decompile_function", name="checksum")["code"]

    # Pointer return types written the usual C way, with '*' against the function name.
    proto = call(mcp, "set_function_prototype", function_address=fns["checksum"],
                 prototype="struct mcp_secret *checksum(struct mcp_secret *s, uint len)")
    assert proto["signature"] == "mcp_secret * checksum(mcp_secret * s, uint len)"


def test_rename_and_delete_data_type(headless):
    _, _, mcp = headless
    call(mcp, "create_typedef", name="mcp_tmp", base_type="int")
    renamed = call(mcp, "rename_data_type", name="mcp_tmp", new_name="mcp_tmp2")
    assert renamed == {"old_path": "/ghidra-mcp/mcp_tmp", "data_type": {
        "name": "mcp_tmp2", "path": "/ghidra-mcp/mcp_tmp2", "kind": "typedef", "size": 4}}
    tool_error(mcp, "get_data_type", "NOT_FOUND", name="/ghidra-mcp/mcp_tmp")
    assert call(mcp, "delete_data_type", name="mcp_tmp2")["path"] == "/ghidra-mcp/mcp_tmp2"
    tool_error(mcp, "get_data_type", "NOT_FOUND", name="/ghidra-mcp/mcp_tmp2")
    tool_error(mcp, "delete_data_type", "INVALID_PARAMETER", name="int")
    tool_error(mcp, "rename_data_type", "NAME_CONFLICT", name="mcp_mode", new_name="mcp_handle")


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
