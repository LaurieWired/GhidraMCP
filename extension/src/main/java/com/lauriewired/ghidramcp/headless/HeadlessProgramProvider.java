package com.lauriewired.ghidramcp.headless;

import java.util.Set;
import java.util.function.Supplier;

import com.lauriewired.ghidramcp.core.ProgramProvider;

import ghidra.program.model.listing.Program;

/**
 * Targets a single program opened by a headless launcher. The launcher owns the program's
 * lifecycle (saving, releasing); this provider only exposes it.
 */
public class HeadlessProgramProvider implements ProgramProvider {

	private final Program program;

	public HeadlessProgramProvider(Program program) {
		this.program = program;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public String mode() {
		return "headless";
	}

	@Override
	public Set<String> capabilities() {
		return Set.of();
	}

	@Override
	public <T> T runWrite(Supplier<T> action) {
		return action.get();
	}
}
