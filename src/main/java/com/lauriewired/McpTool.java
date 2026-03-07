package com.lauriewired;

class McpTool {
    final String    name;
    final String    description;
    final JsonValue inputSchema;

    McpTool(String name, String description, JsonValue inputSchema) {
        this.name        = name;
        this.description = description;
        this.inputSchema = inputSchema;
    }
}
