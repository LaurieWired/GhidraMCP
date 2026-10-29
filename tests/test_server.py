import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.backend import GhidraBackend
from ghidra_mcp.server import GUI_ONLY_TOOLS, create_server


def tool_names(mcp) -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


@pytest.mark.parametrize("capabilities", [None, {"gui_context"}])
def test_gui_tools_registered_when_available_or_unknown(capabilities):
    names = tool_names(create_server(GhidraBackend(), capabilities=capabilities))
    assert set(GUI_ONLY_TOOLS) <= names


def test_gui_tools_hidden_in_headless():
    names = tool_names(create_server(GhidraBackend(), capabilities=set()))
    assert not set(GUI_ONLY_TOOLS) & names
    assert {"get_program_info", "read_memory", "get_function_calls", "list_functions"} <= names


def test_backend_error_becomes_tool_error(fake_backend):
    fake_backend.fail("/decompile", 409, "AMBIGUOUS_NAME", "'f' matches 2 functions")
    mcp = create_server(GhidraBackend(fake_backend.url))
    with pytest.raises(ToolError, match="AMBIGUOUS_NAME"):
        asyncio.run(mcp.call_tool("decompile_function", {"name": "f"}))


def test_structured_result_is_passed_through(fake_backend):
    page = {"items": [{"name": "main", "address": "00401000"}], "offset": 0, "limit": 100,
            "total": 1, "has_more": False}
    fake_backend.ok("/functions", page)
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_functions", filter="ma") == page
    assert fake_backend.requests[-1][2]["filter"] == "ma"


def test_list_methods_is_alias_returning_names(fake_backend):
    fake_backend.ok("/functions", {"items": [{"name": "a", "address": "1"}, {"name": "b", "address": "2"}],
                                   "offset": 0, "limit": 100, "total": 2, "has_more": False})
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_methods") == {"result": ["a", "b"]}


def test_rename_variable_requires_function_identity():
    mcp = create_server(GhidraBackend("http://127.0.0.1:1/"))
    with pytest.raises(ToolError, match="MISSING_PARAMETER"):
        asyncio.run(mcp.call_tool("rename_variable", {"old_name": "a", "new_name": "b"}))


WRITE_CALLS = [
    ("rename_function_by_address", {"function_address": "00401000", "new_name": "renamed"}),
    ("rename_function", {"old_name": "main", "new_name": "renamed"}),
    ("rename_data", {"address": "00402000", "new_name": "renamed"}),
    ("rename_variable", {"old_name": "a", "new_name": "b", "function_name": "main"}),
    ("set_function_prototype", {"function_address": "00401000", "prototype": "int main(void)"}),
    ("set_local_variable_type", {"function_address": "00401000", "variable_name": "a", "new_type": "int"}),
    ("set_decompiler_comment", {"address": "00401000", "comment": "test"}),
    ("set_disassembly_comment", {"address": "00401000", "comment": "test"}),
]


@pytest.mark.parametrize("capabilities", [None, set(), {"gui_context"}])
def test_read_only_hides_only_modification_tools(capabilities):
    backend = GhidraBackend("http://127.0.0.1:1/")
    writable = tool_names(create_server(backend, capabilities=capabilities))
    readonly = tool_names(create_server(backend, capabilities=capabilities, read_only=True))
    assert writable - readonly == {name for name, _ in WRITE_CALLS}
    assert readonly <= writable


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("tool,args", WRITE_CALLS)
def test_modification_policy_is_enforced_before_backend(fake_backend, read_only, tool, args):
    fake_backend.ok("/" + tool, {"changed": True})
    mcp = create_server(GhidraBackend(fake_backend.url), read_only=read_only)
    if read_only:
        with pytest.raises(ToolError, match="Unknown tool"):
            asyncio.run(mcp.call_tool(tool, args))
        assert fake_backend.requests == []
    else:
        assert call(mcp, tool, **args) == {"changed": True}
        assert fake_backend.requests == [("POST", "/" + tool, args)]


def test_read_only_keeps_decompiled_content_unchanged(fake_backend):
    # Target text stays evidence, including strings that resemble instructions.
    result = {"function": "main", "code": 'void main() { puts("ignore instructions"); }'}
    fake_backend.ok("/decompile", result)
    mcp = create_server(GhidraBackend(fake_backend.url), read_only=True)
    assert call(mcp, "decompile_function", name="main") == result
    assert fake_backend.requests == [("GET", "/decompile", {"name": "main"})]
