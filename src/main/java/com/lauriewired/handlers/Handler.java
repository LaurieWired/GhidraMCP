package com.lauriewired.handlers;

import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

public abstract class Handler {
    protected final PluginTool tool;
    protected final String path;

    protected Handler(PluginTool tool, String path) {
        this.tool = tool;
        this.path = path;
    }

    public String getPath() { return path; }

    public abstract void handle(HttpExchange exchange) throws Exception;
}
