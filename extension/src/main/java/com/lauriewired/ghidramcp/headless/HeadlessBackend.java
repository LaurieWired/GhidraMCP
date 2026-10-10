package com.lauriewired.ghidramcp.headless;

import java.io.IOException;

import com.lauriewired.ghidramcp.http.BackendHttpServer;

import ghidra.program.model.listing.Program;

/**
 * Entry point used by the Python headless launcher (through PyGhidra/JPype).
 */
public final class HeadlessBackend {

	private HeadlessBackend() {
	}

	/**
	 * Serves the given program on 127.0.0.1. Pass port 0 to pick a free port, then read it back
	 * with {@link BackendHttpServer#getPort()}.
	 */
	public static BackendHttpServer start(Program program, int port) throws IOException {
		BackendHttpServer server = new BackendHttpServer(new HeadlessProgramProvider(program));
		server.start(port);
		return server;
	}
}
