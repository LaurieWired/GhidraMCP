# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a specific address in the decompiler (pseudocode) view.

    Use this for adding high-level code explanations, algorithm descriptions, or
    logic flow notes that help understand the decompiled code. Comments appear as
    pre-comments in the pseudocode display.

    Common use cases:
    - Explain complex logic or algorithm patterns
    - Document variable usage or data flow
    - Add context about code purpose or behavior
    - Note suspicious or interesting code patterns

    To remove an existing comment, pass an empty string ("") as the comment.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a specific address in the disassembly (listing) view.

    Use this for adding line-specific notes about assembly instructions. Comments
    appear at the end of the line (EOL) in the disassembly listing.

    Common use cases:
    - Explain individual instruction behavior
    - Note register values or memory accesses
    - Document low-level implementation details
    - Mark interesting assembly patterns

    To remove an existing comment, pass an empty string ("") as the comment.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_plate_comment(address: str, comment: str) -> str:
    """
    Set a plate comment for a specific address. Plate comments are displayed
    prominently at the top of the Listing view, making them ideal for important
    high-level notes.

    Use plate comments for:
    - Function summaries or overviews
    - Important warnings or security notes
    - High-level behavioral descriptions
    - Cross-references to related functions

    Plate comments are the most visible comment type in Ghidra and are perfect
    for information that should be immediately visible when navigating to an address.

    To remove an existing plate comment, pass an empty string ("") as the comment.
    """
    return safe_post("set_plate_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100) -> list:
    """
    列出程序中所有定义的数据类型路径。

    此函数返回 Ghidra 程序中所有可用的数据类型,包括基本类型、
    结构体、联合体、枚举类型、函数定义等。数据类型以其完整路径名
    形式返回(如 "/uint", "/windows/BYTE" 等)。

    Args:
        offset: 分页偏移量 (default: 0)
        limit: 返回的最大数量 (default: 100)

    Returns:
        数据类型路径列表,每行一个完整路径

    Examples:
        >>> list_data_types(offset=0, limit=10)
        ['/byte', '/char', '/double', '/float', '/int', ...]
    """
    return safe_get("data_types", {"offset": offset, "limit": limit})

@mcp.tool()
def search_data_types(name: str, case_sensitive: bool = False, offset: int = 0, limit: int = 100) -> list:
    """
    根据名称关键词搜索数据类型。

    此函数在所有数据类型中搜索包含指定关键词的类型路径。搜索是模糊匹配,
    会返回所有包含搜索关键词的数据类型路径。

    Args:
        name: 搜索关键词 (必需)
        case_sensitive: 是否大小写敏感 (default: False)
        offset: 分页偏移量 (default: 0)
        limit: 返回的最大数量 (default: 100)

    Returns:
        匹配的数据类型路径列表,每行一个完整路径

    Examples:
        >>> search_data_types(name="int", limit=5)
        ['/int', '/int[]', '/pointer', '/uint', '/wchar_t']

        >>> search_data_types(name="BYTE", case_sensitive=True)
        ['/windows/BYTE']

        >>> search_data_types(name="byte", case_sensitive=False)
        ['/byte', '/uchar', '/windows/BYTE', ...]
    """
    return safe_get("data_types/search", {"name": name, "case_sensitive": case_sensitive, "offset": offset, "limit": limit})

@mcp.tool()
def get_data_type(path: str) -> str:
    """
    获取特定数据类型的详细信息。

    此函数返回指定数据类型的完整详细信息,包括类型名称、路径、
    大小、描述等。对于结构体类型,还包括字段列表;对于枚举类型,
    还包括枚举值列表。

    Args:
        path: 数据类型的完整路径或相对路径
              例如: "int", "/int", "/MyTypes/MyStruct"

    Returns:
        JSON 格式的数据类型详细信息,包含:
        - path: 完整路径
        - name: 类型名称
        - categoryPath: 类别路径
        - length: 类型长度(字节数)
        - description: 类型描述
        - isDeleted: 是否已删除
        - type: 类型类别(BuiltIn, Structure, Enum, Union, Typedef, FunctionDefinition等)

        对于结构体,额外包含:
        - fields: 字段列表,每个字段包含 name, offset, length, dataType, comment

        对于枚举,额外包含:
        - values: 枚举值列表,每个值包含 name, value, comment

        对于 Typedef,额外包含:
        - baseType: 基础类型路径

        对于函数定义,额外包含:
        - returnType: 返回类型
        - hasVarArgs: 是否有可变参数

    Examples:
        >>> get_data_type("int")
        '{"path": "/int", "name": "int", "categoryPath": "/", ...}'

        >>> get_data_type("/windows/BYTE")
        '{"path": "/windows/BYTE", "name": "BYTE", ...}'
    """
    # 构建正确的 URL 路径
    url_path = f"data_types/{path.lstrip('/')}"
    return "\n".join(safe_get(url_path))

@mcp.tool()
def create_enum(name: str, category_path: str, size: int, values: list) -> str:
    """
    创建枚举数据类型。

    此函数在 Ghidra 中创建一个新的枚举数据类型。枚举类型可以用于
    表示一组命名的常量值。

    Args:
        name: 枚举类型名称 (必需)
              例如: "Color", "Priority", "Status"

        category_path: 类别路径 (必需)
                      枚举所在的类别路径,例如: "/", "/MyTypes", "/System"

        size: 枚举值的大小(字节数) (必需)
             必须是 1, 2, 4, 或 8
             - 1: 1字节枚举 (适合小范围值,如 0-255)
             - 2: 2字节枚举 (适合中等范围值)
             - 4: 4字节枚举 (最常用,适合大多数情况)
             - 8: 8字节枚举 (适合大范围值)

        values: 枚举值列表 (必需,至少包含一个值)
               每个值是一个字典,包含:
               - name: 枚举值名称 (必需)
               - value: 枚举值 (必需,整数)
               - comment: 枚举值注释 (可选)

               例如:
               [
                   {"name": "RED", "value": 0, "comment": "红色"},
                   {"name": "GREEN", "value": 1, "comment": "绿色"},
                   {"name": "BLUE", "value": 2, "comment": "蓝色"}
               ]

    Returns:
        成功: "Enum created successfully"
        失败: 错误消息,包含失败原因

    Examples:
        >>> create_enum(
        ...     name="Color",
        ...     category_path="/MyTypes",
        ...     size=4,
        ...     values=[
        ...         {"name": "RED", "value": 0},
        ...         {"name": "GREEN", "value": 1},
        ...         {"name": "BLUE", "value": 2}
        ...     ]
        ... )
        'Enum created successfully'

        >>> create_enum(
        ...     name="Priority",
        ...     category_path="/System",
        ...     size=4,
        ...     values=[
        ...         {"name": "LOW", "value": 0, "comment": "低优先级"},
        ...         {"name": "MEDIUM", "value": 1, "comment": "中优先级"},
        ...         {"name": "HIGH", "value": 2, "comment": "高优先级"}
        ...     ]
        ... )
        'Enum created successfully'

    Notes:
        - 枚举名称在同一类别路径下必须唯一
        - 枚举值名称在同一个枚举内必须唯一
        - 枚举值可以重复(多个名称可以对应相同的值)
        - size 参数决定了枚举在内存中的大小
        - 如果枚举已存在,会返回错误消息
    """
    import json

    # 构建请求数据
    data = {
        "name": name,
        "categoryPath": category_path,
        "size": size,
        "values": values
    }

    # 发送 POST 请求
    try:
        url = urljoin(ghidra_server_url, "data_types/enum")
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.encoding = 'utf-8'

        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def create_struct(name: str, category_path: str, fields: list, description: str = "") -> str:
    """
    创建结构体数据类型。

    此函数在 Ghidra 中创建一个新的结构体数据类型。结构体可以包含多个字段,
    每个字段都有自己的数据类型、名称、长度和注释。

    Args:
        name: 结构体名称 (必需)
              例如: "Person", "Point", "Address"

        category_path: 类别路径 (必需)
                      结构体所在的类别路径,例如: "/", "/MyTypes", "/Geometry"

        fields: 字段列表 (必需,至少包含一个字段)
                每个字段是一个字典,包含:
                - name: 字段名称 (必需)
                - dataType: 字段数据类型 (必需)
                           可以是:
                           - 基本类型: "/int", "/uint", "/char", "/uchar", "/longlong", "/bool", "/void"
                           - 指针类型: "/uint8*", "/int*", "/void**"
                           - 自定义类型: "/MyTypes/Address" (必须是已存在的类型)

                - length: 字段长度(字节数) (必需)
                        对于数组类型,这是数组的总长度
                        例如: 32 字节的字符数组

                - comment: 字段注释 (可选)
                          用于描述字段的用途

                例如:
                [
                    {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
                    {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
                    {"name": "address", "dataType": "/MyTypes/Address", "length": 64, "comment": "地址"}
                ]

        description: 结构体描述 (可选)
                    用于描述结构体的用途

    Returns:
        成功: "Structure 'XXX' created successfully in category 'YYY'"
        失败: 错误消息,包含失败原因

    Examples:
        >>> create_struct(
        ...     name="Point",
        ...     category_path="/Geometry",
        ...     fields=[
        ...         {"name": "x", "dataType": "/int", "length": 4},
        ...         {"name": "y", "dataType": "/int", "length": 4}
        ...     ]
        ... )
        "Structure 'Point' created successfully in category '/Geometry'"

        >>> create_struct(
        ...     name="Person",
        ...     category_path="/MyTypes",
        ...     description="人员信息结构体",
        ...     fields=[
        ...         {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
        ...         {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
        ...         {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"}
        ...     ]
        ... )
        "Structure 'Person' created successfully in category '/MyTypes'"

    Notes:
        - 结构体名称在同一类别路径下必须唯一
        - 字段名称在同一个结构体内必须唯一
        - 如果使用自定义类型作为字段类型,该类型必须已经存在
        - length 参数对于数组类型特别重要,它指定了数组占用的总字节数
        - 如果结构体已存在,会返回错误消息
        - 支持嵌套结构体(一个结构体可以包含另一个结构体作为字段)
    """
    import json

    # 构建请求数据
    data = {
        "name": name,
        "categoryPath": category_path,
        "fields": fields
    }

    # 添加可选的描述字段
    if description:
        data["description"] = description

    # 发送 POST 请求
    try:
        url = urljoin(ghidra_server_url, "data_types/struct")
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.encoding = 'utf-8'

        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def create_typedef(name: str, category_path: str, base_data_type: str, is_pointer: bool = False) -> str:
    """
    创建 Typedef(类型定义)。

    此函数在 Ghidra 中创建一个新的 Typedef 数据类型。Typedef 为现有类型
    创建别名,常用于提高代码可读性或简化复杂类型。

    Args:
        name: Typedef 名称 (必需)
              例如: "MyIntPtr", "PersonPtr", "UserID"

        category_path: 类别路径 (必需)
                      Typedef 所在的类别路径,例如: "/", "/MyTypes", "/System"

        base_data_type: 基础数据类型 (必需)
                       Typedef 指向的基础类型,可以是:
                       - 基本类型: "/int", "/uint", "/char", "/void"
                       - 自定义类型: "/MyTypes/Person", "/windows/BYTE"
                       - 其他已存在的任何类型

        is_pointer: 是否为指针类型 (可选,默认 False)
                   如果为 True,创建一个指针类型的 Typedef
                   例如: isPointer=True 时,相当于创建 "Person*" 的别名

    Returns:
        成功: "Typedef 'XXX' created successfully in category 'YYY'"
        失败: 错误消息,包含失败原因

    Examples:
        >>> create_typedef(
        ...     name="MyIntPtr",
        ...     category_path="/MyTypes",
        ...     base_data_type="/int"
        ... )
        "Typedef 'MyIntPtr' created successfully in category '/MyTypes'"

        >>> create_typedef(
        ...     name="PersonPtr",
        ...     category_path="/MyTypes",
        ...     base_data_type="/MyTypes/Person",
        ...     is_pointer=True
        ... )
        "Typedef 'PersonPtr' created successfully in category '/MyTypes'"

        >>> create_typedef(
        ...     name="UserID",
        ...     category_path="/System",
        ...     base_data_type="/uint"
        ... )
        "Typedef 'UserID' created successfully in category '/System'"

    Notes:
        - Typedef 名称在同一类别路径下必须唯一
        - 基础数据类型必须已经存在
        - isPointer=True 时,会自动创建指向基础类型的指针 Typedef
        - Typedef 不会创建新的数据类型,只是为现有类型创建别名
        - 常用于提高代码可读性(如用 UserID 代替 uint)
    """
    import json

    # 构建请求数据
    data = {
        "name": name,
        "categoryPath": category_path,
        "baseDataType": base_data_type,
        "isPointer": is_pointer
    }

    # 发送 POST 请求
    try:
        url = urljoin(ghidra_server_url, "data_types/typedef")
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.encoding = 'utf-8'

        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def create_union(name: str, category_path: str, fields: list, description: str = "") -> str:
    """
    创建联合体 (Union) 数据类型。

    此函数在 Ghidra 中创建一个新的联合体数据类型。联合体允许在相同的
    内存位置存储不同类型的数据,所有字段共享同一块内存空间。

    Args:
        name: 联合体名称 (必需)
              例如: "Variant", "Data", "Value"

        category_path: 类别路径 (必需)
                      联合体所在的类别路径,例如: "/", "/MyTypes", "/Primitives"

        fields: 字段列表 (必需,至少包含一个字段)
                每个字段是一个字典,包含:
                - name: 字段名称 (必需)
                - dataType: 字段数据类型 (必需)
                           可以是:
                           - 基本类型: "/int", "/uint", "/char", "/float", "/double"
                           - 指针类型: "/void*", "/int*", "/uint8**"
                           - 自定义类型: "/MyTypes/Person", "/windows/BYTE" (必须是已存在的类型)

                - length: 字段长度(字节数) (必需)
                        对于数组类型,这是数组的总长度

                - comment: 字段注释 (可选)
                          用于描述字段的用途

                例如:
                [
                    {"name": "asInt", "dataType": "/int", "length": 4, "comment": "As integer"},
                    {"name": "asFloat", "dataType": "/float", "length": 4, "comment": "As float"},
                    {"name": "asBytes", "dataType": "/uchar", "length": 4, "comment": "As 4 bytes"}
                ]

        description: 联合体描述 (可选)
                    用于描述联合体的用途

    Returns:
        成功: "Union 'XXX' created successfully in category 'YYY'"
        失败: 错误消息,包含失败原因

    Examples:
        >>> create_union(
        ...     name="IntFloat",
        ...     category_path="/Primitives",
        ...     fields=[
        ...         {"name": "asInt", "dataType": "/int", "length": 4},
        ...         {"name": "asFloat", "dataType": "/float", "length": 4}
        ...     ]
        ... )
        "Union 'IntFloat' created successfully in category '/Primitives'"

        >>> create_union(
        ...     name="Variant",
        ...     category_path="/MyTypes",
        ...     description="可变数据类型联合体",
        ...     fields=[
        ...         {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 64, "comment": "作为 Person 结构体"},
        ...         {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"},
        ...         {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4, "comment": "作为 Color 枚举"}
        ...     ]
        ... )
        "Union 'Variant' created successfully in category '/MyTypes'"

    Notes:
        - 联合体名称在同一类别路径下必须唯一
        - 字段名称在同一个联合体内必须唯一
        - 联合体的所有字段共享同一块内存,大小等于最大字段的大小
        - 如果使用自定义类型作为字段类型,该类型必须已经存在
        - 支持嵌套联合体(一个联合体可以包含另一个联合体作为字段)
        - 支持联合体包含结构体、枚举、Typedef 等复杂类型
        - 适用于需要在不同类型之间共享内存的场景
    """
    import json

    # 构建请求数据
    data = {
        "name": name,
        "categoryPath": category_path,
        "fields": fields
    }

    # 添加可选的描述字段
    if description:
        data["description"] = description

    # 发送 POST 请求
    try:
        url = urljoin(ghidra_server_url, "data_types/union")
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.encoding = 'utf-8'

        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

