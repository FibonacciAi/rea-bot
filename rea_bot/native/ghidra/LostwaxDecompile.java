// Lostwax headless export. Applies caller-supplied names, then writes functions and C.
//@category Lostwax

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class LostwaxDecompile extends GhidraScript {
	private String outPath;
	private long sourceBase;
	private int limit = 16;
	private int decompTimeout = 60;
	private final List<long[]> names = new ArrayList<long[]>();
	private final List<String> nameText = new ArrayList<String>();
	private final List<long[]> params = new ArrayList<long[]>();
	private final List<String> paramTypes = new ArrayList<String>();
	private final List<String> paramNames = new ArrayList<String>();
	private final List<long[]> returns = new ArrayList<long[]>();
	private final List<String> returnTypes = new ArrayList<String>();
	private final List<Long> hints = new ArrayList<Long>();
	private final List<String[]> externs = new ArrayList<String[]>();

	@Override
	public void run() throws Exception {
		if (getScriptArgs().length < 1) {
			throw new IllegalArgumentException("LostwaxDecompile needs a config path.");
		}
		File configFile = new File(getScriptArgs()[0]).getCanonicalFile();
		parse(Files.readAllLines(configFile.toPath(), StandardCharsets.UTF_8));
		if (outPath == null) {
			throw new IllegalArgumentException("LostwaxDecompile config has no out path.");
		}
		File expectedOutput = new File(configFile.getParentFile(), "out.json").getCanonicalFile();
		if (!expectedOutput.equals(new File(outPath).getCanonicalFile())) {
			throw new IllegalArgumentException("Report output must be out.json beside the private config");
		}
		long imageBase = currentProgram.getImageBase().getOffset();
		int namesApplied = applyNames(imageBase);
		int paramsApplied = applyParams(imageBase) + applyExterns();
		applyReturns(imageBase);

		Set<Function> chosen = new LinkedHashSet<Function>();
		FunctionManager manager = currentProgram.getFunctionManager();
		if (limit <= 0) {
			FunctionIterator every = manager.getFunctions(true);
			while (every.hasNext()) {
				Function function = every.next();
				if (!function.isExternal()) {
					chosen.add(function);
				}
			}
		} else {
			Address entryPoint = null;
			AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
			if (entries.hasNext()) {
				entryPoint = entries.next();
			}
			if (entryPoint != null) {
				Function entry = manager.getFunctionAt(entryPoint);
				if (entry == null) {
					entry = getFunctionContaining(entryPoint);
				}
				if (entry != null && !entry.isExternal()) {
					chosen.add(entry);
				}
			}
			for (Long hint : hints) {
				if (chosen.size() >= limit) {
					break;
				}
				Function function = functionAt(hint.longValue(), sourceBase, imageBase);
				if (function != null && !function.isExternal()) {
					chosen.add(function);
				}
			}
			FunctionIterator named = manager.getFunctions(true);
			while (named.hasNext() && chosen.size() < limit) {
				Function function = named.next();
				String label = function.getName();
				if ("main".equals(label) || "add".equals(label) || "entry".equals(label) || "_start".equals(label)) {
					chosen.add(function);
				}
			}
		}

		List<String> decompiled = new ArrayList<String>();
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(currentProgram)) {
				throw new IllegalStateException("Decompiler did not open: " + decompiler.getLastMessage());
			}
			for (Function function : chosen) {
				monitor.checkCancelled();
				DecompileResults result = decompiler.decompileFunction(function, decompTimeout, monitor);
				String code = "";
				boolean completed = result != null && result.decompileCompleted() && result.getDecompiledFunction() != null;
				if (completed) {
					code = result.getDecompiledFunction().getC();
					if (code == null) {
						code = "";
					}
				}
				boolean truncated = code.length() > 200000;
				if (truncated) {
					code = code.substring(0, 200000);
				}
				decompiled.add(functionJson(function, imageBase, code, completed, truncated));
			}
		} finally {
			decompiler.dispose();
		}

		StringBuilder json = new StringBuilder(1 << 20);
		json.append("{\"ok\":true,\"imagebase\":\"").append(hex(imageBase)).append('"');
		json.append(",\"language\":").append(quote(currentProgram.getLanguage().getLanguageID().getIdAsString()));
		json.append(",\"compiler\":").append(quote(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()));
		json.append(",\"names_applied\":").append(namesApplied);
		json.append(",\"params_applied\":").append(paramsApplied);
		int internal = 0;
		int external = 0;
		json.append(",\"functions\":[");
		boolean first = true;
		FunctionIterator functions = manager.getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			if (!first) {
				json.append(',');
			}
			first = false;
			internal++;
			json.append(functionJson(function, imageBase, null, false, false));
		}
		FunctionIterator externals = manager.getExternalFunctions();
		while (externals.hasNext()) {
			Function function = externals.next();
			if (!first) {
				json.append(',');
			}
			first = false;
			external++;
			json.append(functionJson(function, imageBase, null, false, false));
		}
		json.append("],\"internal\":").append(internal);
		json.append(",\"external\":").append(external);
		json.append(",\"decompiled\":[");
		for (int i = 0; i < decompiled.size(); i++) {
			if (i > 0) {
				json.append(',');
			}
			json.append(decompiled.get(i));
		}
		json.append("]}");
		Files.write(new File(outPath).toPath(), json.toString().getBytes(StandardCharsets.UTF_8));
	}

	private void parse(List<String> lines) {
		Set<String> controls = new LinkedHashSet<String>();
		for (String line : lines) {
			if (line.isEmpty() || line.charAt(0) == '#') {
				continue;
			}
			String[] parts = line.split("\t", -1);
			String kind = parts[0];
			boolean control = "out".equals(kind) || "source_base".equals(kind) || "limit".equals(kind) || "decomp_timeout".equals(kind);
			int expected = control || "hint".equals(kind) ? 2 : "name".equals(kind) || "ret".equals(kind) ? 3 : "param".equals(kind) ? 5 : -1;
			if ((expected < 0 && !("extern".equals(kind) && parts.length >= 3)) || (expected >= 0 && parts.length != expected)) {
				throw new IllegalArgumentException("Unknown directive or invalid field count");
			}
			if (control && !controls.add(kind)) {
				throw new IllegalArgumentException("Duplicate control directive");
			}
			for (String field : parts) {
				for (int i = 0; i < field.length(); i++) {
					if (field.charAt(i) < 32 || field.charAt(i) == 127) {
						throw new IllegalArgumentException("Control character in config field");
					}
				}
			}
			if ("out".equals(kind) && parts.length == 2) {
				outPath = parts[1];
			} else if ("source_base".equals(kind) && parts.length == 2) {
				sourceBase = Long.parseUnsignedLong(parts[1], 16);
			} else if ("limit".equals(kind) && parts.length == 2) {
				limit = Integer.parseInt(parts[1]);
			} else if ("decomp_timeout".equals(kind) && parts.length == 2) {
				decompTimeout = Integer.parseInt(parts[1]);
			} else if ("name".equals(kind) && parts.length == 3) {
				names.add(new long[] {Long.parseUnsignedLong(parts[1], 16)});
				nameText.add(parts[2]);
			} else if ("param".equals(kind) && parts.length == 5) {
				params.add(new long[] {Long.parseUnsignedLong(parts[1], 16), Long.parseLong(parts[2])});
				paramTypes.add(parts[3]);
				paramNames.add(parts[4]);
			} else if ("ret".equals(kind) && parts.length == 3) {
				returns.add(new long[] {Long.parseUnsignedLong(parts[1], 16)});
				returnTypes.add(parts[2]);
			} else if ("hint".equals(kind) && parts.length == 2) {
				hints.add(Long.parseUnsignedLong(parts[1], 16));
			} else if ("extern".equals(kind) && parts.length >= 3) {
				String[] row = new String[parts.length - 1];
				System.arraycopy(parts, 1, row, 0, row.length);
				externs.add(row);
			}
		}
	}

	private int applyNames(long imageBase) throws Exception {
		int applied = 0;
		int tx = currentProgram.startTransaction("lostwax-names");
		boolean committed = false;
		try {
			for (int i = 0; i < names.size(); i++) {
				Function function = functionAt(names.get(i)[0], sourceBase, imageBase);
				if (function == null) {
					continue;
				}
				try {
					function.setName(nameText.get(i), SourceType.USER_DEFINED);
					applied++;
				} catch (Exception ignored) {
					// A duplicate or rejected name leaves the existing Ghidra name in place.
				}
			}
			committed = true;
		} finally {
			currentProgram.endTransaction(tx, committed);
		}
		return applied;
	}

	private int applyParams(long imageBase) throws Exception {
		Map<Long, List<Integer>> grouped = new LinkedHashMap<Long, List<Integer>>();
		for (int i = 0; i < params.size(); i++) {
			Long addr = Long.valueOf(params.get(i)[0]);
			List<Integer> rows = grouped.get(addr);
			if (rows == null) {
				rows = new ArrayList<Integer>();
				grouped.put(addr, rows);
			}
			rows.add(Integer.valueOf(i));
		}
		int applied = 0;
		int tx = currentProgram.startTransaction("lostwax-params");
		boolean committed = false;
		try {
			for (Map.Entry<Long, List<Integer>> entry : grouped.entrySet()) {
				Function function = functionAt(entry.getKey().longValue(), sourceBase, imageBase);
				if (function == null) {
					continue;
				}
				applied += writeParams(function, entry.getValue());
			}
			committed = true;
		} finally {
			currentProgram.endTransaction(tx, committed);
		}
		return applied;
	}

	private int writeParams(Function function, List<Integer> rows) {
		int max = -1;
		boolean[] present = new boolean[64];
		for (Integer rowObj : rows) {
			int index = (int) params.get(rowObj.intValue())[1];
			if (index < 0 || index >= present.length) {
				return 0;
			}
			present[index] = true;
			if (index > max) {
				max = index;
			}
		}
		boolean dense = max >= 0;
		for (int i = 0; dense && i <= max; i++) {
			dense = present[i];
		}
		if (!dense) {
			return 0;
		}
		if (function.getParameterCount() == max + 1) {
			int applied = 0;
			for (Integer rowObj : rows) {
				int row = rowObj.intValue();
				int index = (int) params.get(row)[1];
				Parameter parameter = function.getParameter(index);
				DataType type = resolveType(paramTypes.get(row));
				try {
					parameter.setName(paramNames.get(row), SourceType.USER_DEFINED);
					applied++;
					if (type != null) {
						parameter.setDataType(type, SourceType.USER_DEFINED);
					}
				} catch (Exception ignored) {
					// Keep Ghidra's storage when the supplied type does not fit.
				}
			}
			return applied;
		}
		return replaceParams(function, rows, max) ? max + 1 : 0;
	}

	private boolean replaceParams(Function function, List<Integer> rows, int max) {
		try {
			Variable[] vars = new Variable[max + 1];
			for (Integer rowObj : rows) {
				int row = rowObj.intValue();
				int index = (int) params.get(row)[1];
				DataType type = resolveType(paramTypes.get(row));
				if (type == null) {
					type = IntegerDataType.dataType;
				}
				vars[index] = new ParameterImpl(paramNames.get(row), type, currentProgram, SourceType.USER_DEFINED);
			}
			for (int i = 0; i < vars.length; i++) {
				if (vars[i] == null) {
					return false;
				}
			}
			function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.USER_DEFINED, vars);
			return true;
		} catch (Exception ignored) {
			return false;
		}
	}

	private int applyExterns() throws Exception {
		int applied = 0;
		int tx = currentProgram.startTransaction("lostwax-externs");
		boolean committed = false;
		try {
			FunctionIterator functions = currentProgram.getFunctionManager().getExternalFunctions();
			List<Function> externals = new ArrayList<Function>();
			while (functions.hasNext()) {
				externals.add(functions.next());
			}
			for (String[] row : externs) {
				String name = row[0];
				DataType ret = resolveType(row[1]);
				List<String> types = new ArrayList<String>();
				List<String> pnames = new ArrayList<String>();
				for (int i = 2; i < row.length; i++) {
					int bar = row[i].lastIndexOf('|');
					if (bar <= 0) {
						continue;
					}
					String typ = row[i].substring(0, bar).trim();
					String pname = row[i].substring(bar + 1).trim();
					if (typ.isEmpty() || pname.isEmpty() || "...".equals(typ)) {
						continue;
					}
					types.add(typ);
					pnames.add(pname);
				}
				for (Function function : externals) {
					if (!sameImport(function.getName(), name)) {
						continue;
					}
					if (ret != null) {
						try {
							function.setReturnType(ret, SourceType.USER_DEFINED);
						} catch (Exception ignored) {
							// The call still uses the parameter names when the return type is refused.
						}
					}
					if (function.getParameterCount() == pnames.size()) {
						for (int i = 0; i < pnames.size(); i++) {
							DataType type = resolveType(types.get(i));
							try {
								function.getParameter(i).setName(pnames.get(i), SourceType.USER_DEFINED);
								applied++;
								if (type != null) {
									function.getParameter(i).setDataType(type, SourceType.USER_DEFINED);
								}
							} catch (Exception ignored) {
								// Leave the recovered external parameter.
							}
						}
					}
				}
			}
			committed = true;
		} finally {
			currentProgram.endTransaction(tx, committed);
		}
		return applied;
	}

	private void applyReturns(long imageBase) throws Exception {
		int tx = currentProgram.startTransaction("lostwax-returns");
		boolean committed = false;
		try {
			for (int i = 0; i < returns.size(); i++) {
				Function function = functionAt(returns.get(i)[0], sourceBase, imageBase);
				DataType type = resolveType(returnTypes.get(i));
				if (function == null || type == null) {
					continue;
				}
				try {
					function.setReturnType(type, SourceType.USER_DEFINED);
				} catch (Exception ignored) {
					// The decompiler keeps its own return type.
				}
			}
			committed = true;
		} finally {
			currentProgram.endTransaction(tx, committed);
		}
	}

	private static boolean sameImport(String symbol, String catalog) {
		String name = symbol == null ? "" : symbol;
		int at = name.indexOf('@');
		if (at > 0) {
			name = name.substring(0, at);
		}
		if (name.equals(catalog)) {
			return true;
		}
		return name.startsWith("_") && name.substring(1).equals(catalog);
	}

	private Function functionAt(long source, long base, long imageBase) {
		long relocated = source - base + imageBase;
		Function function = functionExact(relocated);
		if (function == null && relocated != source) {
			function = functionExact(source);
		}
		return function;
	}

	private Function functionExact(long offset) {
		try {
			Address address = toAddr(offset);
			if (address == null) {
				return null;
			}
			return getFunctionAt(address);
		} catch (Exception ignored) {
			return null;
		}
	}

	private String functionJson(Function function, long imageBase, String code, boolean completed, boolean truncated) {
		long offset = function.getEntryPoint().getOffset();
		StringBuilder row = new StringBuilder();
		row.append("{\"address\":\"").append(hex(offset)).append('"');
		row.append(",\"name\":").append(quote(function.getName()));
		row.append(",\"external\":").append(function.isExternal());
		String signature = function.getName();
		try {
			signature = function.getPrototypeString(false, false);
		} catch (Exception ignored) {
			signature = function.getName();
		}
		if (signature.length() > 400) {
			signature = signature.substring(0, 400);
		}
		row.append(",\"signature\":").append(quote(signature));
		row.append(",\"param_count\":").append(function.getParameterCount());
		if (code != null) {
			row.append(",\"decompile_completed\":").append(completed);
			row.append(",\"c_truncated\":").append(truncated);
			row.append(",\"c\":").append(quote(code));
			row.append(",\"calls\":[");
			boolean first = true;
			try {
				for (Function callee : function.getCalledFunctions(monitor)) {
					if (!first) {
						row.append(',');
					}
					first = false;
					row.append("{\"name\":").append(quote(callee.getName()));
					row.append(",\"address\":\"").append(hex(callee.getEntryPoint().getOffset())).append("\"}");
					if (row.length() > 200000) {
						break;
					}
				}
			} catch (Exception ignored) {
				// The function body is still useful without its call list.
			}
			row.append(']');
		}
		row.append('}');
		return row.toString();
	}

	private DataType resolveType(String text) {
		if (text == null) {
			return null;
		}
		String name = text.trim();
		if (name.isEmpty() || "unknown".equals(name)) {
			return null;
		}
		int pointers = 0;
		while (name.endsWith("*")) {
			pointers++;
			name = name.substring(0, name.length() - 1).trim();
		}
		DataType base;
		if ("void".equals(name)) {
			base = VoidDataType.dataType;
		} else if ("bool".equals(name) || "_Bool".equals(name) || "boolean".equals(name)) {
			base = BooleanDataType.dataType;
		} else if ("char".equals(name) || "unsigned char".equals(name) || "signed char".equals(name)) {
			base = CharDataType.dataType;
		} else if ("short".equals(name) || "unsigned short".equals(name)) {
			base = ShortDataType.dataType;
		} else if ("int".equals(name) || "unsigned int".equals(name) || "signed int".equals(name)) {
			base = IntegerDataType.dataType;
		} else if ("long".equals(name) || "unsigned long".equals(name) || "long long".equals(name)
				|| "unsigned long long".equals(name)) {
			base = LongLongDataType.dataType;
		} else if ("float".equals(name)) {
			base = FloatDataType.dataType;
		} else if ("double".equals(name)) {
			base = DoubleDataType.dataType;
		} else {
			return null;
		}
		DataType current = base;
		for (int i = 0; i < pointers; i++) {
			current = new PointerDataType(current);
		}
		return current;
	}

	private static String hex(long value) {
		return "0x" + Long.toHexString(value);
	}

	private static String quote(String value) {
		if (value == null) {
			value = "";
		}
		StringBuilder out = new StringBuilder(value.length() + 2);
		out.append('"');
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '"' || c == '\\') {
				out.append('\\').append(c);
			} else if (c == '\n') {
				out.append("\\n");
			} else if (c == '\r') {
				out.append("\\r");
			} else if (c == '\t') {
				out.append("\\t");
			} else if (c < 0x20) {
				out.append(String.format("\\u%04x", (int) c));
			} else {
				out.append(c);
			}
		}
		out.append('"');
		return out.toString();
	}
}
