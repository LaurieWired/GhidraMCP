package com.lauriewired.ghidramcp.gui;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import com.lauriewired.ghidramcp.core.McpException;
import com.lauriewired.ghidramcp.core.ProgramProvider;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Targets the program that is active in the Ghidra tool. Writes run on the Swing thread.
 */
public class GuiProgramProvider implements ProgramProvider {

	private final PluginTool tool;

	public GuiProgramProvider(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public Program getProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	@Override
	public String mode() {
		return "gui";
	}

	@Override
	public Set<String> capabilities() {
		return Set.of(CAP_GUI_CONTEXT);
	}

	@Override
	public Address getCurrentAddress() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null) {
			throw McpException.unsupported("Code viewer service not available");
		}
		ProgramLocation location = service.getCurrentLocation();
		if (location == null || location.getAddress() == null) {
			throw McpException.notFound("No current location in the listing");
		}
		return location.getAddress();
	}

	@Override
	public DataTypeQueryService getDataTypeService() {
		return tool.getService(DataTypeManagerService.class);
	}

	@Override
	public <T> T runWrite(Supplier<T> action) {
		if (SwingUtilities.isEventDispatchThread()) {
			return action.get();
		}
		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<RuntimeException> failure = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					result.set(action.get());
				}
				catch (RuntimeException e) {
					failure.set(e);
				}
			});
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw McpException.failed("Interrupted while waiting for the Swing thread", e);
		}
		catch (InvocationTargetException e) {
			throw McpException.failed("Write failed on the Swing thread: " + e.getCause(), e);
		}
		if (failure.get() != null) {
			throw failure.get();
		}
		return result.get();
	}
}
