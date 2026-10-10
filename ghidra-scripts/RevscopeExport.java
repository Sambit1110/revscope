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
import java.util.List;

import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.EntryPointCommand;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.Application;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class RevscopeExport extends HeadlessScript {

	private static final String SCHEMA = "revscope.ghidra-export/2";
	private static final String SCRIPT_VERSION = "2";
	private static final int MAX_NAME_CHARS = 1024;
	private static final int MAX_SIGNATURE_CHARS = 4096;
	private static final int MAX_LABEL_CHARS = 256;
	private static final int MAX_ENTRY_POINTS = 256;
	private static final int MAX_SYMBOLS = 16;
	private static final int MAX_WARNINGS = 32;
	private static final int MAX_WARNING_CHARS = 1024;
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
				decompiler.setOptions(warningsOnlyOptions());
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

	/**
	 * The program's entry point as its file header declares it, read with the
	 * same Ghidra format parsers the loaders use, over the original file bytes.
	 * Ghidra's "external entry points" also include exported symbols, so they
	 * cannot tell the program entry apart; the header can. Only ELF e_entry and
	 * Mach-O LC_MAIN are read; anything else is reported as unavailable.
	 */
	private String programEntry(Program program) {
		String format = program.getExecutableFormat();
		List<FileBytes> files = program.getMemory().getAllFileBytes();
		if (files.isEmpty()) {
			return entryJson("unavailable", null, "Ghidra holds no original file bytes for this program.");
		}
		FileBytesProvider bytes = new FileBytesProvider(files.get(0));
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long imageBase = program.getImageBase().getOffset();
		try {
			if (ElfLoader.ELF_NAME.equals(format)) {
				ElfHeader elf = new ElfHeader(bytes, message -> {});
				elf.parse();
				if (elf.e_entry() == 0) {
					return entryJson("unavailable", null, "The ELF header declares no entry point.");
				}
				// Ghidra may load a position-independent file at another base.
				return entryAt(program, space.getAddress(elf.e_entry() + (imageBase - elf.getImageBase())), "elf-header");
			}
			if (MachoLoader.MACH_O_NAME.equals(format)) {
				MachHeader mach = new MachHeader(bytes).parse();
				List<EntryPointCommand> mains = mach.getLoadCommands(EntryPointCommand.class);
				SegmentCommand text = mach.getSegment("__TEXT");
				if (mains.isEmpty() || text == null) {
					return entryJson("unavailable", null,
						"The Mach-O file has no LC_MAIN entry point; other entry forms are not read.");
				}
				long slide = imageBase - text.getVMaddress();
				long entry = text.getVMaddress() + mains.get(0).getEntryOffset() - text.getFileOffset() + slide;
				return entryAt(program, space.getAddress(entry), "macho-lc-main");
			}
			return entryJson("unavailable", null,
				"Revscope reads program entry points from ELF and Mach-O headers only.");
		}
		catch (Exception e) {
			return entryJson("unavailable", null,
				"Ghidra's format parser could not read the header (" + e.getClass().getSimpleName() + ").");
		}
	}

	private static String entryAt(Program program, Address entry, String source) {
		return program.getMemory().contains(entry) ? entryJson(source, entry, null)
				: entryJson("unavailable", null, "The header's entry point lies outside the loaded program.");
	}

	private static String entryJson(String source, Address entry, String reason) {
		return "{\"source\":" + json(source) + ",\"addresses\":" + (entry == null ? "[]" : "[" + json(hex(entry)) + "]") +
			",\"reason\":" + (reason == null ? "null" : json(reason)) + "}";
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
			",\"program_entry\":" + programEntry(program) +
			",\"external_entry_points\":" + entries + "}" +
			",\"analysis\":{\"timed_out\":" + analysisTimeoutOccurred() +
			",\"decompiler\":" + json(decompilerState) + "}" +
			",\"limits\":{\"max_functions\":" + maxFunctions + ",\"decompile\":" + decompile +
			",\"decompile_timeout_s\":" + decompileTimeoutSeconds + "}}";
	}

	/**
	 * Every symbol at the function's entry, primary first, then by name. One
	 * address can carry several names: on Mach-O, Ghidra's loader adds an
	 * `entry` label at the program entry next to the symbol-table name, and
	 * both are marked IMPORTED. Revscope decides how to present them.
	 */
	private static String symbolsAt(Function function) {
		Symbol[] symbols = function.getProgram().getSymbolTable().getSymbols(function.getEntryPoint());
		java.util.Arrays.sort(symbols, (a, b) -> a.isPrimary() != b.isPrimary() ? (a.isPrimary() ? -1 : 1)
				: a.getName().compareTo(b.getName()));
		StringBuilder builder = new StringBuilder("[");
		for (int index = 0; index < symbols.length && index < MAX_SYMBOLS; index++) {
			builder.append(index == 0 ? "" : ",")
				.append("{\"name\":").append(json(nonEmpty(truncate(symbols[index].getName(), MAX_NAME_CHARS))))
				.append(",\"source\":").append(json(nameSource(symbols[index])))
				.append(",\"primary\":").append(symbols[index].isPrimary()).append("}");
		}
		return builder.append("]").toString();
	}

	private String functionRecord(Function function) {
		Symbol symbol = function.getSymbol();
		// Unknown is reported as null, never as a convention named "unknown".
		String convention = function.hasUnknownCallingConventionName() ? null : function.getCallingConventionName();
		String signature = function.getSignature().getPrototypeString();
		return "{\"type\":\"function\",\"address\":" + json(hex(function.getEntryPoint())) +
			",\"name\":" + json(nonEmpty(truncate(function.getName(), MAX_NAME_CHARS))) +
			",\"name_source\":" + json(nameSource(symbol)) +
			",\"body_bytes\":" + function.getBody().getNumAddresses() +
			",\"symbols\":" + symbolsAt(function) +
			",\"is_thunk\":" + function.isThunk() +
			",\"is_external_entry_point\":" +
			function.getProgram().getSymbolTable().isExternalEntryPoint(function.getEntryPoint()) +
			",\"calling_convention\":" + nullableText(convention, MAX_LABEL_CHARS) +
			",\"signature\":" + nullableText(signature, MAX_SIGNATURE_CHARS) +
			",\"signature_source\":" + json(sourceName(function.getSignatureSource())) + "}";
	}

	private String decompile(DecompInterface decompiler, Function function, int timeoutSeconds,
			int maxPseudocodeChars) {
		DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);
		if (results == null) {
			return decompilationRecord(function, "failed", null, false);
		}
		String noSignature = ",\"decompiler_signature\":null,\"decompiler_calling_convention\":null";
		if (results.isTimedOut()) {
			return decompilationRecord(function, "timeout", null, false, noSignature + diagnostics(results));
		}
		DecompiledFunction decompiled = results.getDecompiledFunction();
		if (!results.decompileCompleted() || decompiled == null || decompiled.getC() == null) {
			return decompilationRecord(function, "failed", null, false, noSignature + diagnostics(results));
		}
		String code = decompiled.getC();
		boolean truncated = code.length() > maxPseudocodeChars;
		String kept = truncated ? truncate(code, maxPseudocodeChars) : code;
		String view = decompilerView(results, decompiled) + diagnostics(results);
		String line = decompilationRecord(function, "ok", kept, truncated, view);
		// Escaping can grow a line; shorten until it fits Revscope's line limit.
		while (line.getBytes(StandardCharsets.UTF_8).length > MAX_LINE_BYTES && kept.length() > 0) {
			kept = truncate(kept, kept.length() / 2);
			line = decompilationRecord(function, "ok", kept, true, view);
		}
		return line;
	}

	/**
	 * The decompiler's own signature and calling-convention model, kept apart
	 * from the function's stored signature: the decompiler infers them and does
	 * not write them back.
	 */
	private static String decompilerView(DecompileResults results, DecompiledFunction decompiled) {
		String signature = decompiled.getSignature();
		if (signature != null) {
			signature = signature.trim();
			if (signature.endsWith(";")) {
				signature = signature.substring(0, signature.length() - 1).trim();
			}
		}
		HighFunction high = results.getHighFunction();
		String model = high == null ? null : high.getFunctionPrototype().getModelName();
		if ("unknown".equals(model)) {
			model = null;
		}
		return ",\"decompiler_signature\":" + nullableText(signature, MAX_SIGNATURE_CHARS) +
			",\"decompiler_calling_convention\":" + nullableText(model, MAX_LABEL_CHARS);
	}

	private static String decompilationRecord(Function function, String status, String code,
			boolean truncated) {
		return decompilationRecord(function, status, code, truncated,
			",\"decompiler_signature\":null,\"decompiler_calling_convention\":null,\"warnings\":[],\"error_message\":null");
	}

	/**
	 * Decompiler options that keep the decompiler's own warning comments and
	 * drop every listing comment (PRE, PLATE, POST, EOL, function header). With
	 * that, every comment token in the output is a decompiler warning: they are
	 * identified by their token type and comment class, not by reading text.
	 */
	private static DecompileOptions warningsOnlyOptions() {
		DecompileOptions options = new DecompileOptions();
		options.setPRECommentIncluded(false);
		options.setPLATECommentIncluded(false);
		options.setPOSTCommentIncluded(false);
		options.setEOLCommentIncluded(false);
		options.setHeadCommentIncluded(false);
		options.setWARNCommentIncluded(true);
		return options;
	}

	/**
	 * The decompiler's warnings and error message. Ghidra 12.1.4 exposes
	 * warnings only as comment tokens in the C markup, one word per token,
	 * framed by comment delimiters; the delimiters separate one warning from
	 * the next. getErrorMessage() is empty when there are only warnings.
	 */
	private static String diagnostics(DecompileResults results) {
		List<String> warnings = new java.util.ArrayList<>();
		if (results.getCCodeMarkup() != null) {
			collectWarnings(results.getCCodeMarkup(), new StringBuilder(), warnings);
		}
		StringBuilder list = new StringBuilder("[");
		for (int index = 0; index < warnings.size() && index < MAX_WARNINGS; index++) {
			list.append(index == 0 ? "" : ",").append(json(truncate(warnings.get(index), MAX_WARNING_CHARS)));
		}
		list.append("]");
		String error = results.getErrorMessage();
		error = error == null || error.trim().isEmpty() ? null : error.trim();
		return ",\"warnings\":" + list + ",\"error_message\":" + nullableText(error, MAX_WARNING_CHARS);
	}

	/** Walk the markup tree; consecutive comment tokens between delimiters form one warning. */
	private static void collectWarnings(ClangNode node, StringBuilder current, List<String> warnings) {
		if (node instanceof ClangCommentToken) {
			String text = ((ClangToken) node).getText().trim();
			if (text.startsWith("/*")) {
				current.setLength(0);
				text = text.substring(2).trim();
			}
			boolean ends = text.endsWith("*/");
			if (ends) {
				text = text.substring(0, text.length() - 2).trim();
			}
			if (!text.isEmpty()) {
				current.append(current.length() == 0 ? "" : " ").append(text);
			}
			if (ends && current.length() > 0) {
				warnings.add(current.toString());
				current.setLength(0);
			}
		}
		for (int index = 0; index < node.numChildren(); index++) {
			collectWarnings(node.Child(index), current, warnings);
		}
	}

	private static String decompilationRecord(Function function, String status, String code,
			boolean truncated, String view) {
		return "{\"type\":\"decompilation\",\"address\":" + json(hex(function.getEntryPoint())) +
			",\"status\":" + json(status) + ",\"pseudocode\":" + (code == null ? "null" : json(code)) +
			",\"truncated\":" + truncated + view + "}";
	}

	private static String nameSource(Symbol symbol) {
		return symbol == null ? "other" : sourceName(symbol.getSource());
	}

	/** Ghidra's SourceType as Revscope names it. */
	private static String sourceName(SourceType source) {
		if (source == null) {
			return "other";
		}
		switch (source.name()) {
			case "IMPORTED":
				return "imported";
			case "ANALYSIS":
				return "analysis";
			case "DEFAULT":
				return "default";
			case "USER_DEFINED":
				return "user";
			case "AI":
				return "ai";
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
