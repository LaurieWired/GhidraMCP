package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;

public final class GetCurrentAddress extends Handler {
    public GetCurrentAddress(PluginTool tool) {
        super(tool, "/get_current_address");
    }

    public void handle(HttpExchange exchange) throws IOException {
        sendResponse(exchange, getCurrentAddress());
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }
}
