"""MCP tool definitions."""

from __future__ import annotations

import json
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from ghidra_mcp.backend import BackendError, GhidraBackend

CAP_GUI_CONTEXT = "gui_context"

GUI_ONLY_TOOLS = ("get_current_address", "get_current_function")

INSTRUCTIONS = """\
Tools for reverse engineering the program open in Ghidra. Call get_program_info first to confirm
which binary you are working on. Addresses are hex strings such as "0x401000". List tools are
paginated: pass offset/limit and check has_more. Prefer the address-based tools for modifications,
since function names can be ambiguous. To define structs, unions, enums, and typedefs prefer
define_c_types with plain C (no #include or #define); inspect types with get_data_type and use them
with apply_data_type, set_local_variable_type, or set_function_prototype.
"""

Result = dict[str, Any]

OnConflict = Literal["error", "replace", "keep"]


class StructField(BaseModel):
    """A struct or union field."""

    type: str = Field(description='Field type, e.g. "int", "char[16]", "struct node *".')
    name: str | None = Field(None, description="Field name; omit for Ghidra's default name.")
    offset: int | None = Field(
        None, description="Byte offset in a non-packed struct; omit to append after the last field."
    )
    comment: str | None = None
    bit_size: int | None = Field(None, description="Make this a bit field of this many bits.")
    bit_offset: int | None = Field(
        None, description="Bit offset within the storage unit at `offset` (non-packed structs)."
    )


def _fields_json(fields: list[StructField] | None) -> str | None:
    if fields is None:
        return None
    return json.dumps([f.model_dump(exclude_none=True) for f in fields])


def create_server(
    backend: GhidraBackend,
    host: str = "127.0.0.1",
    port: int = 8081,
    capabilities: set[str] | None = None,
) -> FastMCP:
    """Builds the MCP server.

    `capabilities` comes from the backend's /health. When it is None (backend not reachable at
    startup) every tool is registered.
    """
    mcp = FastMCP("ghidra-mcp", instructions=INSTRUCTIONS, host=host, port=port)
    gui_context = capabilities is None or CAP_GUI_CONTEXT in capabilities

    def call(method: str, endpoint: str, **params: Any) -> Any:
        try:
            return backend.request(method, endpoint, params)
        except BackendError as e:
            raise ToolError(str(e)) from e

    def get(endpoint: str, **params: Any) -> Any:
        return call("GET", endpoint, **params)

    def post(endpoint: str, **params: Any) -> Any:
        return call("POST", endpoint, **params)

    # ---- Program ---------------------------------------------------------------------------

    @mcp.tool()
    def get_program_info() -> Result:
        """Identify the target program: name, format, language/architecture, compiler spec,
        image base, address range, size, entry points, and hashes."""
        return get("program_info")

    # ---- Listings --------------------------------------------------------------------------

    @mcp.tool()
    def list_functions(offset: int = 0, limit: int = 100, filter: str | None = None) -> Result:
        """List functions (name and entry address), optionally filtered by a case-insensitive
        substring of the name."""
        return get("functions", offset=offset, limit=limit, filter=filter)

    @mcp.tool()
    def list_methods(offset: int = 0, limit: int = 100) -> list[str]:
        """Deprecated: use list_functions. Lists function names only."""
        page = get("functions", offset=offset, limit=limit)
        return [f["name"] for f in page["items"]]

    @mcp.tool()
    def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> Result:
        """Search for functions whose name contains the given substring (case-insensitive)."""
        if not query:
            raise ToolError("[MISSING_PARAMETER] query is required")
        return get("functions", offset=offset, limit=limit, filter=query)

    @mcp.tool()
    def list_classes(offset: int = 0, limit: int = 100) -> Result:
        """List class namespaces (fully qualified names)."""
        return get("classes", offset=offset, limit=limit)

    @mcp.tool()
    def list_namespaces(offset: int = 0, limit: int = 100) -> Result:
        """List all non-global namespaces (fully qualified names)."""
        return get("namespaces", offset=offset, limit=limit)

    @mcp.tool()
    def list_segments(offset: int = 0, limit: int = 100) -> Result:
        """List memory blocks with address range, size, and permissions."""
        return get("segments", offset=offset, limit=limit)

    @mcp.tool()
    def list_imports(offset: int = 0, limit: int = 100) -> Result:
        """List imported (external) symbols and their libraries."""
        return get("imports", offset=offset, limit=limit)

    @mcp.tool()
    def list_exports(offset: int = 0, limit: int = 100) -> Result:
        """List exported symbols / entry points."""
        return get("exports", offset=offset, limit=limit)

    @mcp.tool()
    def list_data_items(offset: int = 0, limit: int = 100) -> Result:
        """List defined data with address, label, type, and value."""
        return get("data", offset=offset, limit=limit)

    @mcp.tool()
    def list_strings(offset: int = 0, limit: int = 200, filter: str | None = None) -> Result:
        """List defined strings with their addresses, optionally filtered by a case-insensitive
        substring of the content."""
        return get("strings", offset=offset, limit=limit, filter=filter)

    # ---- Functions -------------------------------------------------------------------------

    @mcp.tool()
    def get_function_by_address(address: str) -> Result:
        """Get the function at or containing an address: name, signature, body range,
        calling convention."""
        return get("function", address=address)

    if gui_context:

        @mcp.tool()
        def get_current_address() -> Result:
            """Get the address currently selected in the Ghidra GUI listing."""
            return get("current_address")

        @mcp.tool()
        def get_current_function() -> Result:
            """Get the function containing the address currently selected in the Ghidra GUI."""
            return get("current_function")

    @mcp.tool()
    def decompile_function(name: str) -> Result:
        """Decompile a function by name and return C pseudocode. Fails if the name is ambiguous;
        use decompile_function_by_address in that case."""
        return get("decompile", name=name)

    @mcp.tool()
    def decompile_function_by_address(address: str) -> Result:
        """Decompile the function at or containing an address and return C pseudocode."""
        return get("decompile_function", address=address)

    @mcp.tool()
    def disassemble_function(address: str, offset: int = 0, limit: int = 500) -> Result:
        """Disassemble the instructions in a function's body (address, bytes, instruction,
        end-of-line comment)."""
        return get("disassemble_function", address=address, offset=offset, limit=limit)

    # ---- References ------------------------------------------------------------------------

    @mcp.tool()
    def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> Result:
        """List references to an address, with the function each reference comes from."""
        return get("xrefs_to", address=address, offset=offset, limit=limit)

    @mcp.tool()
    def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> Result:
        """List references from a single instruction or data address."""
        return get("xrefs_from", address=address, offset=offset, limit=limit)

    @mcp.tool()
    def get_function_xrefs(
        name: str | None = None, address: str | None = None, offset: int = 0, limit: int = 100
    ) -> Result:
        """List references to a function's entry point, by name or (preferably) address."""
        if not name and not address:
            raise ToolError("[MISSING_PARAMETER] name or address is required")
        return get("function_xrefs", name=name, address=address, offset=offset, limit=limit)

    @mcp.tool()
    def get_function_calls(
        address: str,
        direction: Literal["both", "callers", "callees"] = "both",
        offset: int = 0,
        limit: int = 100,
    ) -> Result:
        """Function-level call graph, one level deep. Callers are call sites that reach this
        function; callees are calls made from anywhere in its body, including indirect calls
        (direct=false). offset/limit apply to each list separately."""
        return get(
            "function_calls", address=address, direction=direction, offset=offset, limit=limit
        )

    # ---- Memory ----------------------------------------------------------------------------

    @mcp.tool()
    def read_memory(address: str, length: int = 64) -> Result:
        """Read up to 4096 bytes of program memory as hex and ASCII. Unmapped or uninitialized
        bytes are shown as '??' and listed in `gaps`."""
        return get("read_memory", address=address, length=length)

    # ---- Modifications ---------------------------------------------------------------------

    @mcp.tool()
    def rename_function_by_address(function_address: str, new_name: str) -> Result:
        """Rename the function at or containing an address."""
        return post(
            "rename_function_by_address", function_address=function_address, new_name=new_name
        )

    @mcp.tool()
    def rename_function(old_name: str, new_name: str) -> Result:
        """Rename a function by its current name. Fails if the name is ambiguous; prefer
        rename_function_by_address."""
        return post("rename_function", old_name=old_name, new_name=new_name)

    @mcp.tool()
    def rename_data(address: str, new_name: str) -> Result:
        """Rename the label of defined data (or an existing symbol) at an address."""
        return post("rename_data", address=address, new_name=new_name)

    @mcp.tool()
    def rename_variable(
        old_name: str,
        new_name: str,
        function_address: str | None = None,
        function_name: str | None = None,
    ) -> Result:
        """Rename a local variable or parameter as shown in the decompiler. Identify the function
        by function_address (preferred) or function_name."""
        if not function_address and not function_name:
            raise ToolError("[MISSING_PARAMETER] function_address or function_name is required")
        return post(
            "rename_variable",
            function_address=function_address,
            function_name=function_name,
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool()
    def set_function_prototype(function_address: str, prototype: str) -> Result:
        """Set a function's signature from a C prototype, e.g. "int foo(char *buf, int len)"."""
        return post("set_function_prototype", function_address=function_address, prototype=prototype)

    @mcp.tool()
    def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> Result:
        """Set the data type of a decompiler variable, e.g. "char *", "DWORD", "MY_STRUCT *"."""
        return post(
            "set_local_variable_type",
            function_address=function_address,
            variable_name=variable_name,
            new_type=new_type,
        )

    @mcp.tool()
    def set_decompiler_comment(address: str, comment: str) -> Result:
        """Set the pre-comment at an address (shown in the decompiler). An empty comment clears
        it."""
        return post("set_decompiler_comment", address=address, comment=comment)

    @mcp.tool()
    def set_disassembly_comment(address: str, comment: str) -> Result:
        """Set the end-of-line comment at an address (shown in the disassembly). An empty comment
        clears it."""
        return post("set_disassembly_comment", address=address, comment=comment)

    # ---- Data types ------------------------------------------------------------------------

    @mcp.tool()
    def list_data_types(
        filter: str | None = None,
        category: str | None = None,
        kind: Literal["struct", "union", "enum", "typedef", "function", "pointer", "array",
                      "builtin", "other"] | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Result:
        """List data types (name, path, kind, size), optionally filtered by a case-insensitive
        name substring, a category such as "/ghidra-mcp", and kind. Pointers and arrays are only
        listed when kind asks for them."""
        return get("data_types", filter=filter, category=category, kind=kind, offset=offset,
                   limit=limit)

    @mcp.tool()
    def get_data_type(name: str) -> Result:
        """Get a data type's full definition: fields with offsets for structs and unions, values
        for enums, the base type of typedefs, and a C declaration. `name` may be a C type name or
        a full path such as "/ghidra-mcp/foo"."""
        return get("data_type", name=name)

    @mcp.tool()
    def list_data_type_categories(offset: int = 0, limit: int = 200) -> Result:
        """List data type category paths."""
        return get("data_type_categories", offset=offset, limit=limit)

    @mcp.tool()
    def define_c_types(
        source: str, category: str | None = None, on_conflict: OnConflict = "error"
    ) -> Result:
        """Define data types from C declarations: structs, unions, enums, typedefs, and function
        pointer types, e.g. "struct node { int value; struct node *next; };". Declarations may use
        types that already exist in the program. The preprocessor is not run, so #include and
        #define are not allowed. Types go into `category` (default "/ghidra-mcp"). on_conflict
        decides what happens when a type of the same name already exists there."""
        return post("define_c_types", source=source, category=category, on_conflict=on_conflict)

    @mcp.tool()
    def create_struct(
        name: str,
        fields: list[StructField] | None = None,
        size: int | None = None,
        packing_enabled: bool = False,
        category: str | None = None,
        description: str | None = None,
        on_conflict: OnConflict = "error",
    ) -> Result:
        """Create a struct. With packing_enabled=false (the default) fields are placed exactly at
        their byte offsets and gaps stay undefined; `size` pre-sizes the struct, which is useful
        when only some fields are known. With packing_enabled=true Ghidra lays fields out using
        the compiler's alignment rules and offsets must be omitted. Fields may refer to the struct
        itself, e.g. "name *"."""
        return post(
            "create_struct",
            name=name,
            fields=_fields_json(fields),
            size=size,
            packing_enabled=packing_enabled,
            category=category,
            description=description,
            on_conflict=on_conflict,
        )

    @mcp.tool()
    def create_union(
        name: str,
        fields: list[StructField],
        category: str | None = None,
        description: str | None = None,
        on_conflict: OnConflict = "error",
    ) -> Result:
        """Create a union. Field offsets must be omitted."""
        return post(
            "create_union",
            name=name,
            fields=_fields_json(fields),
            category=category,
            description=description,
            on_conflict=on_conflict,
        )

    @mcp.tool()
    def create_enum(
        name: str,
        values: dict[str, int],
        size: Literal[1, 2, 4, 8] = 4,
        category: str | None = None,
        description: str | None = None,
        on_conflict: OnConflict = "error",
    ) -> Result:
        """Create an enum from a mapping of names to values, e.g. {"RED": 0, "GREEN": 1}. `size`
        is the enum's size in bytes."""
        return post(
            "create_enum",
            name=name,
            values=json.dumps(values),
            size=size,
            category=category,
            description=description,
            on_conflict=on_conflict,
        )

    @mcp.tool()
    def create_typedef(
        name: str, base_type: str, category: str | None = None, on_conflict: OnConflict = "error"
    ) -> Result:
        """Create a typedef, e.g. name="HANDLE_T", base_type="void *"."""
        return post("create_typedef", name=name, base_type=base_type, category=category,
                    on_conflict=on_conflict)

    @mcp.tool()
    def create_function_definition(
        prototype: str, category: str | None = None, on_conflict: OnConflict = "error"
    ) -> Result:
        """Create a function signature type from a C prototype, e.g. "int callback(void *ctx)".
        Use a pointer to it ("callback *") as a struct field or variable type."""
        return post("create_function_definition", prototype=prototype, category=category,
                    on_conflict=on_conflict)

    @mcp.tool()
    def add_struct_field(name: str, field: StructField) -> Result:
        """Add a field to an existing struct or union. In a non-packed struct, a field with an
        offset replaces undefined bytes there (growing the struct if needed); without an offset it
        is appended."""
        return post(
            "add_struct_field", name=name, field=json.dumps(field.model_dump(exclude_none=True))
        )

    @mcp.tool()
    def update_struct_field(
        name: str,
        field_name: str | None = None,
        offset: int | None = None,
        new_name: str | None = None,
        new_type: str | None = None,
        comment: str | None = None,
    ) -> Result:
        """Rename, retype, or comment a struct or union field, identified by field_name or by its
        byte offset (structs only). A larger new type must fit into the undefined bytes after the
        field. An empty comment clears it."""
        if not field_name and offset is None:
            raise ToolError("[MISSING_PARAMETER] field_name or offset is required")
        return post(
            "update_struct_field",
            name=name,
            field_name=field_name,
            offset=offset,
            new_name=new_name,
            new_type=new_type,
            comment=comment,
        )

    @mcp.tool()
    def delete_struct_field(
        name: str, field_name: str | None = None, offset: int | None = None
    ) -> Result:
        """Delete a struct or union field, identified by field_name or by byte offset. In a
        non-packed struct the field's bytes become undefined and later fields keep their
        offsets."""
        if not field_name and offset is None:
            raise ToolError("[MISSING_PARAMETER] field_name or offset is required")
        return post("delete_struct_field", name=name, field_name=field_name, offset=offset)

    @mcp.tool()
    def set_enum_value(
        name: str, value_name: str, value: int, comment: str | None = None
    ) -> Result:
        """Add a value to an enum, or change an existing one."""
        return post("set_enum_value", name=name, value_name=value_name, value=value,
                    comment=comment)

    @mcp.tool()
    def delete_enum_value(name: str, value_name: str) -> Result:
        """Remove a value from an enum."""
        return post("delete_enum_value", name=name, value_name=value_name)

    @mcp.tool()
    def rename_data_type(name: str, new_name: str) -> Result:
        """Rename a data type. Uses of it are updated."""
        return post("rename_data_type", name=name, new_name=new_name)

    @mcp.tool()
    def delete_data_type(name: str) -> Result:
        """Delete a data type. Data, variables, and fields that used it become undefined."""
        return post("delete_data_type", name=name)

    @mcp.tool()
    def apply_data_type(address: str, type: str, clear_existing: bool = False) -> Result:
        """Define data of a type at an address, e.g. lay a struct over a global or vtable. Fails
        if other data is in the way unless clear_existing is true."""
        return post("apply_data_type", address=address, type=type, clear_existing=clear_existing)

    return mcp
