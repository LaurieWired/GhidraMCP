//[STEP 1] Build function hash index from currently open program.
//Run this on your well-documented binary first, then on other versions to merge them.
//The index is saved to: ghidra-mcp/function_hash_index.json
//After indexing, run PropagateFromIndex_Auto to apply documentation to undocumented functions.
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath Tools.1 - Build Hash Index (Auto)
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * Builds a function hash index from the currently open program.
 * 
 * The hash is computed from normalized opcodes that ignore absolute addresses,
 * allowing identical code at different memory locations to be matched across
 * different binary versions.
 * 
 * The index stores:
 * - Function names and plate comments
 * - Function signatures (return type, calling convention, parameters)
 * - Custom data types (structs, enums, typedefs) used by functions
 * 
 * The best-documented version of each function is tracked as "canonical".
 */
public class BuildHashIndex_Auto extends GhidraScript {

    // Path to the hash index file - uses user's home directory for portability
    // Change this path if you want to store the index elsewhere
    private static final String INDEX_FILE = System.getProperty("user.home") +
        java.io.File.separator + "ghidra_function_hash_index.json";
    
    // Statistics
    private int functionsProcessed = 0;
    private int hashesComputed = 0;
    private int newHashes = 0;
    private int updatedCanonical = 0;
    private int dataTypesCollected = 0;
    
    // Track data types we've already serialized
    private Set<String> serializedDataTypes = new HashSet<>();
    private Map<String, Map<String, Object>> dataTypesMap = new LinkedHashMap<>();

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }
        
        String programName = currentProgram.getName();
        String programPath = currentProgram.getDomainFile().getPathname();
        
        println("=".repeat(70));
        println("BUILD FUNCTION HASH INDEX (Enhanced)");
        println("=".repeat(70));
        println("Program: " + programName);
        println("Path: " + programPath);
        println("Index file: " + INDEX_FILE);
        println("");
        println("This version stores: names, plate comments, signatures, and data types");
        println("");
        
        // Load existing index or create new one
        println("Loading existing index...");
        Map<String, Object> index = loadIndex();
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> functions = (Map<String, Map<String, Object>>) 
            index.computeIfAbsent("functions", k -> new LinkedHashMap<>());
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> existingDataTypes = (Map<String, Map<String, Object>>) 
            index.computeIfAbsent("data_types", k -> new LinkedHashMap<>());
        
        // Merge existing data types
        dataTypesMap.putAll(existingDataTypes);
        serializedDataTypes.addAll(existingDataTypes.keySet());
        
        int existingCount = functions.size();
        int existingDataTypeCount = existingDataTypes.size();
        println("  Existing hashes in index: " + existingCount);
        println("  Existing data types in index: " + existingDataTypeCount);
        println("");
        
        // Process all functions in current program
        println("Processing functions...");
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            processFunction(func, programName, programPath, functions);
            
            functionsProcessed++;
            if (functionsProcessed % 500 == 0) {
                println("  Processed " + functionsProcessed + " functions...");
            }
        }
        
        // Update metadata
        index.put("version", "2.0");
        index.put("last_updated", Instant.now().toString());
        index.put("total_unique_hashes", functions.size());
        index.put("total_data_types", dataTypesMap.size());
        index.put("data_types", dataTypesMap);
        
        // Save index
        println("");
        println("Saving index...");
        saveIndex(index);
        
        // Summary
        println("");
        println("=".repeat(70));
        println("SUMMARY");
        println("=".repeat(70));
        println("Functions processed: " + functionsProcessed);
        println("Hashes computed: " + hashesComputed);
        println("New unique hashes added: " + newHashes);
        println("Canonical entries updated: " + updatedCanonical);
        println("Data types collected: " + dataTypesCollected);
        println("Total unique hashes in index: " + functions.size());
        println("Total data types in index: " + dataTypesMap.size());
        println("");
        println("Index saved to: " + INDEX_FILE);
    }

    /**
     * Process a single function - compute hash and update index.
     */
    private void processFunction(Function func, String programName, String programPath,
                                  Map<String, Map<String, Object>> functions) {
        // Skip thunks and external functions
        if (func.isThunk() || func.isExternal()) {
            return;
        }
        
        // Compute normalized hash
        String hash = computeFunctionHash(func);
        if (hash == null) {
            return;
        }
        hashesComputed++;
        
        // Gather function metadata
        boolean hasCustomName = !func.getName().startsWith("FUN_");
        String plateComment = func.getComment();
        boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
        String address = func.getEntryPoint().toString();
        
        // Get function signature details
        Map<String, Object> signature = extractSignature(func);
        
        // Calculate completeness score (enhanced)
        int completenessScore = 0;
        if (hasCustomName) completenessScore += 30;
        if (hasPlateComment) completenessScore += 30;
        
        // Check return type (not void/undefined)
        DataType returnType = func.getReturnType();
        boolean hasCustomReturnType = returnType != null && 
            !returnType.getName().equals("undefined") &&
            !returnType.getName().equals("void");
        if (hasCustomReturnType) completenessScore += 15;
        
        // Check for named parameters
        Parameter[] params = func.getParameters();
        int namedParamCount = 0;
        int typedParamCount = 0;
        for (Parameter p : params) {
            if (!p.getName().startsWith("param_")) namedParamCount++;
            DataType pType = p.getDataType();
            if (pType != null && !pType.getName().equals("undefined") && 
                !pType.getName().equals("undefined4")) {
                typedParamCount++;
            }
        }
        if (namedParamCount > 0) completenessScore += 15;
        if (typedParamCount > 0) completenessScore += 10;
        
        // Create instance entry for this program
        Map<String, Object> instance = new LinkedHashMap<>();
        instance.put("program", programName);
        instance.put("program_path", programPath);
        instance.put("address", address);
        instance.put("name", func.getName());
        instance.put("has_custom_name", hasCustomName);
        instance.put("has_plate_comment", hasPlateComment);
        if (hasPlateComment) {
            instance.put("plate_comment", plateComment);
        }
        instance.put("signature", signature);
        instance.put("completeness_score", completenessScore);
        
        // Get or create hash entry
        Map<String, Object> hashEntry = functions.get(hash);
        if (hashEntry == null) {
            // New hash - create entry
            hashEntry = new LinkedHashMap<>();
            hashEntry.put("canonical", instance);
            hashEntry.put("instances", new ArrayList<Map<String, Object>>());
            functions.put(hash, hashEntry);
            newHashes++;
        }
        
        // Add/update instance in the list
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");
        
        // Remove existing instance for this program path if present
        instances.removeIf(inst -> programPath.equals(inst.get("program_path")));
        instances.add(instance);
        
        // Update canonical if this instance is better documented
        @SuppressWarnings("unchecked")
        Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
        
        boolean shouldUpdateCanonical = false;
        
        if (canonical == null) {
            shouldUpdateCanonical = true;
        } else {
            int canonicalScore = ((Number) canonical.getOrDefault("completeness_score", 0)).intValue();
            boolean canonicalHasPlateComment = canonical.containsKey("plate_comment") && 
                canonical.get("plate_comment") != null;
            boolean canonicalHasSignature = canonical.containsKey("signature") && 
                canonical.get("signature") != null;
            
            // Update if: higher score, OR same score but we have more data
            if (completenessScore > canonicalScore) {
                shouldUpdateCanonical = true;
            } else if (completenessScore == canonicalScore) {
                // Prefer entry with actual plate_comment text over one without
                if (hasPlateComment && !canonicalHasPlateComment) {
                    shouldUpdateCanonical = true;
                }
                // Prefer entry with signature if canonical lacks it
                else if (signature != null && !canonicalHasSignature) {
                    shouldUpdateCanonical = true;
                }
            }
        }
        
        if (shouldUpdateCanonical) {
            hashEntry.put("canonical", instance);
            if (canonical != null && !programPath.equals(canonical.get("program_path"))) {
                updatedCanonical++;
            }
        }
    }

    /**
     * Extract function signature including return type and parameters.
     */
    private Map<String, Object> extractSignature(Function func) {
        Map<String, Object> sig = new LinkedHashMap<>();
        
        // Calling convention
        sig.put("calling_convention", func.getCallingConventionName());
        
        // Return type
        DataType returnType = func.getReturnType();
        sig.put("return_type", serializeDataType(returnType));
        
        // Parameters
        List<Map<String, Object>> params = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            Map<String, Object> param = new LinkedHashMap<>();
            param.put("name", p.getName());
            param.put("ordinal", p.getOrdinal());
            param.put("type", serializeDataType(p.getDataType()));
            params.add(param);
        }
        sig.put("parameters", params);
        
        return sig;
    }

    /**
     * Serialize a data type, recursively handling composite types.
     */
    private Map<String, Object> serializeDataType(DataType dt) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        if (dt == null) {
            result.put("name", "undefined");
            result.put("kind", "primitive");
            return result;
        }
        
        String dtName = dt.getName();
        String dtPath = dt.getPathName();
        result.put("name", dtName);
        result.put("path", dtPath);
        result.put("size", dt.getLength());
        
        // Handle pointer types
        if (dt instanceof Pointer) {
            result.put("kind", "pointer");
            Pointer ptr = (Pointer) dt;
            DataType pointedTo = ptr.getDataType();
            if (pointedTo != null) {
                result.put("pointed_to", serializeDataType(pointedTo));
            }
            return result;
        }
        
        // Handle array types
        if (dt instanceof Array) {
            result.put("kind", "array");
            Array arr = (Array) dt;
            result.put("element_count", arr.getNumElements());
            result.put("element_type", serializeDataType(arr.getDataType()));
            return result;
        }
        
        // Handle typedef
        if (dt instanceof TypeDef) {
            result.put("kind", "typedef");
            TypeDef td = (TypeDef) dt;
            result.put("base_type", serializeDataType(td.getBaseDataType()));
            collectDataType(dt);
            return result;
        }
        
        // Handle structure types
        if (dt instanceof Structure) {
            result.put("kind", "struct");
            collectDataType(dt);
            return result;
        }
        
        // Handle union types
        if (dt instanceof Union) {
            result.put("kind", "union");
            collectDataType(dt);
            return result;
        }
        
        // Handle enum types
        if (dt instanceof ghidra.program.model.data.Enum) {
            result.put("kind", "enum");
            collectDataType(dt);
            return result;
        }
        
        // Handle function definition
        if (dt instanceof FunctionDefinition) {
            result.put("kind", "function_def");
            return result;
        }
        
        // Primitive/built-in types
        result.put("kind", "primitive");
        return result;
    }

    /**
     * Collect a custom data type definition for storage in the index.
     */
    private void collectDataType(DataType dt) {
        String dtPath = dt.getPathName();
        
        // Skip if already collected
        if (serializedDataTypes.contains(dtPath)) {
            return;
        }
        serializedDataTypes.add(dtPath);
        dataTypesCollected++;
        
        Map<String, Object> dtDef = new LinkedHashMap<>();
        dtDef.put("name", dt.getName());
        dtDef.put("path", dtPath);
        dtDef.put("size", dt.getLength());
        dtDef.put("category", dt.getCategoryPath().toString());
        
        if (dt instanceof Structure) {
            dtDef.put("kind", "struct");
            Structure struct = (Structure) dt;
            dtDef.put("description", struct.getDescription());
            
            List<Map<String, Object>> fields = new ArrayList<>();
            for (DataTypeComponent comp : struct.getComponents()) {
                Map<String, Object> field = new LinkedHashMap<>();
                field.put("offset", comp.getOffset());
                field.put("name", comp.getFieldName());
                field.put("type", serializeDataType(comp.getDataType()));
                field.put("size", comp.getLength());
                String comment = comp.getComment();
                if (comment != null && !comment.isEmpty()) {
                    field.put("comment", comment);
                }
                fields.add(field);
            }
            dtDef.put("fields", fields);
            
        } else if (dt instanceof Union) {
            dtDef.put("kind", "union");
            Union union = (Union) dt;
            dtDef.put("description", union.getDescription());
            
            List<Map<String, Object>> fields = new ArrayList<>();
            for (DataTypeComponent comp : union.getComponents()) {
                Map<String, Object> field = new LinkedHashMap<>();
                field.put("name", comp.getFieldName());
                field.put("type", serializeDataType(comp.getDataType()));
                field.put("size", comp.getLength());
                String comment = comp.getComment();
                if (comment != null && !comment.isEmpty()) {
                    field.put("comment", comment);
                }
                fields.add(field);
            }
            dtDef.put("fields", fields);
            
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            dtDef.put("kind", "enum");
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
            dtDef.put("description", enumDt.getDescription());
            
            Map<String, Object> values = new LinkedHashMap<>();
            for (String name : enumDt.getNames()) {
                values.put(name, enumDt.getValue(name));
            }
            dtDef.put("values", values);
            
        } else if (dt instanceof TypeDef) {
            dtDef.put("kind", "typedef");
            TypeDef td = (TypeDef) dt;
            dtDef.put("base_type", serializeDataType(td.getBaseDataType()));
        }
        
        dataTypesMap.put(dtPath, dtDef);
    }

    /**
     * Compute a normalized opcode hash for a function.
     * This normalizes addresses to allow matching across different binaries.
     */
    private String computeFunctionHash(Function func) {
        try {
            StringBuilder normalized = new StringBuilder();
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();
            
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                
                // Get mnemonic (operation)
                normalized.append(instr.getMnemonicString());
                normalized.append(" ");
                
                // Normalize operands
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instr.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                // Internal reference - use relative offset
                                long offset = addr.subtract(func.getEntryPoint());
                                normalized.append("REL:").append(offset);
                            } else if (currentProgram.getFunctionManager().getFunctionAt(addr) != null) {
                                // External function call
                                normalized.append("CALL_EXT");
                            } else {
                                // External data reference
                                normalized.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            // Keep small immediates, normalize large ones
                            long value = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(value) < 0x10000) {
                                normalized.append("IMM:").append(value);
                            } else {
                                normalized.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            // Keep register names
                            normalized.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    normalized.append(",");
                }
                normalized.append(";");
            }
            
            // Compute SHA-256 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes());
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
            
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Load existing index from file, or return empty index.
     */
    private Map<String, Object> loadIndex() {
        File file = new File(INDEX_FILE);
        if (!file.exists()) {
            return new LinkedHashMap<>();
        }
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("  Warning: Could not load existing index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    /**
     * Save index to file.
     */
    private void saveIndex(Map<String, Object> index) throws IOException {
        String json = toJson(index, 0);
        Files.write(Paths.get(INDEX_FILE), json.getBytes());
    }

    /**
     * Simple JSON parser (Ghidra scripts don't have easy access to JSON libraries).
     */
    private Map<String, Object> parseJson(String json) {
        // Use Ghidra's built-in Gson if available, otherwise simple parsing
        try {
            Class<?> gsonClass = Class.forName("com.google.gson.Gson");
            Object gson = gsonClass.getConstructor().newInstance();
            java.lang.reflect.Method fromJson = gsonClass.getMethod("fromJson", String.class, Class.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) fromJson.invoke(gson, json, Map.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            // Fallback to empty map if parsing fails
            return new LinkedHashMap<>();
        }
    }

    /**
     * Convert map to JSON string.
     */
    private String toJson(Object obj, int indent) {
        try {
            Class<?> gsonBuilderClass = Class.forName("com.google.gson.GsonBuilder");
            Object builder = gsonBuilderClass.getConstructor().newInstance();
            java.lang.reflect.Method setPrettyPrinting = gsonBuilderClass.getMethod("setPrettyPrinting");
            builder = setPrettyPrinting.invoke(builder);
            java.lang.reflect.Method create = gsonBuilderClass.getMethod("create");
            Object gson = create.invoke(builder);
            java.lang.reflect.Method toJson = gson.getClass().getMethod("toJson", Object.class);
            return (String) toJson.invoke(gson, obj);
        } catch (Exception e) {
            // Fallback to simple formatting
            return simpleToJson(obj, indent);
        }
    }

    /**
     * Simple JSON serialization fallback.
     */
    private String simpleToJson(Object obj, int indent) {
        String indentStr = "  ".repeat(indent);
        String nextIndent = "  ".repeat(indent + 1);
        
        if (obj == null) {
            return "null";
        } else if (obj instanceof String) {
            return "\"" + escapeJson((String) obj) + "\"";
        } else if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        } else if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(",\n");
                first = false;
                sb.append(nextIndent).append("\"").append(escapeJson(entry.getKey())).append("\": ");
                sb.append(simpleToJson(entry.getValue(), indent + 1));
            }
            sb.append("\n").append(indentStr).append("}");
            return sb.toString();
        } else if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) obj;
            if (list.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[\n");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(",\n");
                first = false;
                sb.append(nextIndent).append(simpleToJson(item, indent + 1));
            }
            sb.append("\n").append(indentStr).append("]");
            return sb.toString();
        }
        return "\"" + obj.toString() + "\"";
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
