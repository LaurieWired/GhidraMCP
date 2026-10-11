package com.lauriewired.ghidramcp.core;

import java.util.Set;
import java.util.function.Supplier;

import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Supplies the program that backend requests operate on, and the execution-mode specific
 * pieces (GUI location, where writes must run).
 */
public interface ProgramProvider {

	/** Capability: the user's current location in the GUI is available. */
	String CAP_GUI_CONTEXT = "gui_context";

	/** @return the target program, or null if none is open */
	Program getProgram();

	/** @return "gui" or "headless" */
	String mode();

	Set<String> capabilities();

	default Address getCurrentAddress() {
		throw McpException.unsupported("The current GUI location is not available in " + mode() + " mode");
	}

	/** @return a data type service for type lookups, or null if none is available */
	default DataTypeQueryService getDataTypeService() {
		return null;
	}

	/**
	 * Runs a program-modifying action on the thread that writes must use, and returns its result.
	 * Runtime exceptions thrown by the action propagate to the caller.
	 */
	<T> T runWrite(Supplier<T> action);
}
