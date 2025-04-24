package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ListFunctions extends Handler {
    public ListFunctions(PluginTool tool) {
        super(tool, "/list_functions");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        sendResponse(exchange, listFunctions());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                    func.getName(),
                    func.getEntryPoint()));
        }

        return result.toString();
    }
}
