package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class DecompileFunctionByName extends Handler {
    public DecompileFunctionByName(PluginTool tool) {
        super(tool, "/decompile");
    }

    public void handle(HttpExchange exchange) throws IOException {
        String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        sendResponse(exchange, generateResponse(name));
    }

    private String generateResponse(String name) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                        decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }
}
