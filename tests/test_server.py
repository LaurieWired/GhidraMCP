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


def test_struct_fields_are_sent_as_json(fake_backend):
    fake_backend.ok("/create_struct", {"action": "created", "data_type": {}})
    mcp = create_server(GhidraBackend(fake_backend.url))
    call(mcp, "create_struct", name="hdr", size=16, fields=[
        {"type": "uint", "name": "magic", "offset": 0},
        {"type": "hdr *"},
    ])
    params = fake_backend.requests[-1][2]
    assert json.loads(params["fields"]) == [{"type": "uint", "name": "magic", "offset": 0},
                                            {"type": "hdr *"}]
    assert params["on_conflict"] == "error"
    assert params["packing_enabled"] == "False"


def test_enum_values_are_sent_as_json(fake_backend):
    fake_backend.ok("/create_enum", {"action": "created", "data_type": {}})
    mcp = create_server(GhidraBackend(fake_backend.url))
    call(mcp, "create_enum", name="color", values={"RED": 0, "GREEN": 5}, size=1)
    params = fake_backend.requests[-1][2]
    assert json.loads(params["values"]) == {"RED": 0, "GREEN": 5}
    assert params["size"] == "1"


def test_invalid_on_conflict_is_rejected():
    mcp = create_server(GhidraBackend("http://127.0.0.1:1/"))
    with pytest.raises(ToolError):
        asyncio.run(mcp.call_tool("define_c_types", {"source": "struct a { int x; };",
                                                     "on_conflict": "overwrite"}))


def test_struct_field_edits_require_field_identity():
    mcp = create_server(GhidraBackend("http://127.0.0.1:1/"))
    with pytest.raises(ToolError, match="MISSING_PARAMETER"):
        asyncio.run(mcp.call_tool("update_struct_field", {"name": "a", "new_name": "b"}))
    with pytest.raises(ToolError, match="MISSING_PARAMETER"):
        asyncio.run(mcp.call_tool("delete_struct_field", {"name": "a"}))
