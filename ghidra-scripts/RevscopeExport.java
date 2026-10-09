// Revscope export script for Ghidra headless analysis.
//
// Writes the revscope.ghidra-export/1 format that Revscope validates in
// src/infrastructure/ghidra/exportFormat.ts: one JSON record per line, a
// header, function records each followed by an optional decompilation
// record, and a trailer. Every line is flushed as it is written, so a run
// that is stopped leaves only complete lines, and a missing trailer tells
// Revscope the export is incomplete.
//
// Arguments (from Revscope, never from users):
//   0 export path                1 maximum functions
//   2 decompile (true|false)     3 per-function decompile timeout, seconds
//   4 deadline, epoch ms         5 maximum pseudocode characters
//
// The script only reads the program Ghidra has imported. It never runs the
// input, and it writes nothing except the export file.
//
//@category Revscope
//@runtime Java

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class RevscopeExport extends HeadlessScript {

	private static final String SCHEMA = "revscope.ghidra-export/1";
	private static final String SCRIPT_VERSION = "1";
	private static final int MAX_NAME_CHARS = 1024;
	private static final int MAX_SIGNATURE_CHARS = 4096;
	private static final int MAX_LABEL_CHARS = 256;
	private static final int MAX_ENTRY_POINTS = 256;
	/** Revscope refuses record lines over 256 KiB; stay well below. */
	private static final int MAX_LINE_BYTES = 200_000;

	private BufferedWriter out;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 6) {
			throw new IllegalArgumentException("RevscopeExport expects 6 arguments");
		}
		String exportPath = args[0];
		int maxFunctions = Integer.parseInt(args[1]);
		boolean decompile = Boolean.parseBoolean(args[2]);
		int decompileTimeoutSeconds = Integer.parseInt(args[3]);
		long deadlineEpochMs = Long.parseLong(args[4]);
		int maxPseudocodeChars = Integer.parseInt(args[5]);

		Program program = currentProgram;
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		out = new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(exportPath), StandardCharsets.UTF_8));
		DecompInterface decompiler = null;
		try {
			// The decompiler is a native program; on macOS it must be built locally
			// (support/gradle buildNatives). When it cannot start, the export says so.
			String decompilerState = "not-requested";
			if (decompile) {
				decompiler = new DecompInterface();
				decompiler.setOptions(new DecompileOptions());
				if (decompiler.openProgram(program)) {
					decompilerState = "available";
				}
				else {
					decompiler.dispose();
					decompiler = null;
					decompilerState = "unavailable";
				}
			}
			writeLine(header(program, maxFunctions, decompile, decompileTimeoutSeconds, decompilerState));

			int total = 0;
			FunctionIterator counting = program.getFunctionManager().getFunctions(true);
			while (counting.hasNext()) {
				if (exportable(counting.next(), defaultSpace)) {
					total++;
				}
			}

			int exported = 0;
			boolean limitReached = false;
			boolean deadlineReached = false;
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				Function function = functions.next();
				if (!exportable(function, defaultSpace)) {
					continue;
				}
				if (exported >= maxFunctions) {
					limitReached = true;
					break;
				}
				writeLine(functionRecord(function));
				exported++;
				if (!decompile) {
					continue;
				}
				long remainingMs = deadlineEpochMs - System.currentTimeMillis();
				int timeoutSeconds = (int) Math.min(decompileTimeoutSeconds, remainingMs / 1000);
				if (timeoutSeconds < 1 || monitor.isCancelled()) {
					deadlineReached = true;
					writeLine(decompilationRecord(function, "skipped", null, false));
				}
				else if (decompiler == null) {
					writeLine(decompilationRecord(function, "failed", null, false));
				}
				else {
					writeLine(decompile(decompiler, function, timeoutSeconds, maxPseudocodeChars));
				}
			}
			String stopped = deadlineReached ? "deadline" : limitReached ? "function-limit" : "complete";
			writeLine("{\"type\":\"trailer\",\"functions_total\":" + total +
				",\"functions_exported\":" + exported + ",\"stopped\":" + json(stopped) + "}");
		}
		finally {
			if (decompiler != null) {
				decompiler.dispose();
			}
			out.close();
		}
	}

	/** Functions with a body in the default address space; others are not exported. */
	private static boolean exportable(Function function, AddressSpace defaultSpace) {
		return !function.isExternal() &&
			function.getEntryPoint().getAddressSpace().equals(defaultSpace);
	}

	// analysisTimeoutOccurred() declares the checked ImproperUseException.
	private String header(Program program, int maxFunctions, boolean decompile,
			int decompileTimeoutSeconds, String decompilerState) throws Exception {
		StringBuilder entries = new StringBuilder("[");
		AddressIterator entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
		int count = 0;
		while (entryPoints.hasNext() && count < MAX_ENTRY_POINTS) {
			Address entry = entryPoints.next();
			if (!entry.isMemoryAddress()) {
				continue;
			}
			entries.append(count == 0 ? "" : ",").append(json(hex(entry)));
			count++;
		}
		entries.append("]");
		String format = program.getExecutableFormat();
		return "{\"type\":\"header\",\"schema\":" + json(SCHEMA) +
			",\"script_version\":" + json(SCRIPT_VERSION) +
			",\"ghidra_version\":" + json(Application.getApplicationVersion()) +
			",\"program\":{" +
			"\"executable_format\":" + json(label(format == null ? "unknown" : format)) +
			",\"language_id\":" + json(label(program.getLanguageID().getIdAsString())) +
			",\"compiler_spec\":" +
			json(label(program.getCompilerSpec().getCompilerSpecID().getIdAsString())) +
			",\"processor\":" + json(label(program.getLanguage().getProcessor().toString())) +
			",\"endian\":" + json(program.getLanguage().isBigEndian() ? "big" : "little") +
			",\"address_size\":" + program.getAddressFactory().getDefaultAddressSpace().getSize() +
			",\"image_base\":" + json(hex(program.getImageBase())) +
			",\"min_address\":" + nullableAddress(program.getMinAddress()) +
			",\"max_address\":" + nullableAddress(program.getMaxAddress()) +
			",\"entry_points\":" + entries + "}" +
			",\"analysis\":{\"timed_out\":" + analysisTimeoutOccurred() +
			",\"decompiler\":" + json(decompilerState) + "}" +
			",\"limits\":{\"max_functions\":" + maxFunctions + ",\"decompile\":" + decompile +
			",\"decompile_timeout_s\":" + decompileTimeoutSeconds + "}}";
	}

	private String functionRecord(Function function) {
		Symbol symbol = function.getSymbol();
		String convention = function.getCallingConventionName();
		String signature = function.getSignature().getPrototypeString();
		return "{\"type\":\"function\",\"address\":" + json(hex(function.getEntryPoint())) +
			",\"name\":" + json(nonEmpty(truncate(function.getName(), MAX_NAME_CHARS))) +
			",\"name_source\":" + json(nameSource(symbol)) +
			",\"body_bytes\":" + function.getBody().getNumAddresses() +
			",\"is_thunk\":" + function.isThunk() +
			",\"calling_convention\":" + nullableText(convention, MAX_LABEL_CHARS) +
			",\"signature\":" + nullableText(signature, MAX_SIGNATURE_CHARS) + "}";
	}

	private String decompile(DecompInterface decompiler, Function function, int timeoutSeconds,
			int maxPseudocodeChars) {
		DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);
		if (results == null) {
			return decompilationRecord(function, "failed", null, false);
		}
		if (results.isTimedOut()) {
			return decompilationRecord(function, "timeout", null, false);
		}
		DecompiledFunction decompiled = results.getDecompiledFunction();
		if (!results.decompileCompleted() || decompiled == null || decompiled.getC() == null) {
			return decompilationRecord(function, "failed", null, false);
		}
		String code = decompiled.getC();
		boolean truncated = code.length() > maxPseudocodeChars;
		String kept = truncated ? truncate(code, maxPseudocodeChars) : code;
		String line = decompilationRecord(function, "ok", kept, truncated);
		// Escaping can grow a line; shorten until it fits Revscope's line limit.
		while (line.getBytes(StandardCharsets.UTF_8).length > MAX_LINE_BYTES && kept.length() > 0) {
			kept = truncate(kept, kept.length() / 2);
			line = decompilationRecord(function, "ok", kept, true);
		}
		return line;
	}

	private static String decompilationRecord(Function function, String status, String code,
			boolean truncated) {
		return "{\"type\":\"decompilation\",\"address\":" + json(hex(function.getEntryPoint())) +
			",\"status\":" + json(status) + ",\"pseudocode\":" + (code == null ? "null" : json(code)) +
			",\"truncated\":" + truncated + "}";
	}

	private static String nameSource(Symbol symbol) {
		if (symbol == null) {
			return "other";
		}
		switch (symbol.getSource().name()) {
			case "IMPORTED":
				return "imported";
			case "ANALYSIS":
				return "analysis";
			case "DEFAULT":
				return "default";
			case "USER_DEFINED":
				return "user";
			default:
				return "other";
		}
	}

	/** Lowercase hexadecimal offset, treating the offset as unsigned. */
	private static String hex(Address address) {
		return "0x" + Long.toHexString(address.getOffset());
	}

	private static String nullableAddress(Address address) {
		return address == null ? "null" : json(hex(address));
	}

	private static String nullableText(String text, int maxChars) {
		return text == null || text.isEmpty() ? "null" : json(truncate(text, maxChars));
	}

	private static String label(String text) {
		return nonEmpty(truncate(text, MAX_LABEL_CHARS));
	}

	private static String nonEmpty(String text) {
		return text == null || text.isEmpty() ? "unnamed" : text;
	}

	/** Cut to at most maxChars without splitting a surrogate pair. */
	private static String truncate(String text, int maxChars) {
		if (text == null || text.length() <= maxChars) {
			return text;
		}
		int end = maxChars;
		if (end > 0 && Character.isHighSurrogate(text.charAt(end - 1))) {
			end--;
		}
		return text.substring(0, end);
	}

	/** A JSON string literal; control characters are escaped. */
	private static String json(String text) {
		StringBuilder builder = new StringBuilder(text.length() + 2).append('"');
		for (int index = 0; index < text.length(); index++) {
			char c = text.charAt(index);
			switch (c) {
				case '"':
					builder.append("\\\"");
					break;
				case '\\':
					builder.append("\\\\");
					break;
				case '\n':
					builder.append("\\n");
					break;
				case '\r':
					builder.append("\\r");
					break;
				case '\t':
					builder.append("\\t");
					break;
				default:
					if (c < 0x20 || c == 0x2028 || c == 0x2029) {
						builder.append(String.format("\\u%04x", (int) c));
					}
					else {
						builder.append(c);
					}
			}
		}
		return builder.append('"').toString();
	}

	private void writeLine(String line) throws IOException {
		out.write(line);
		out.write('\n');
		out.flush();
	}
}
