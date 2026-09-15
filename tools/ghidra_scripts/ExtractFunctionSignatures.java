// ExtractFunctionSignatures.java
//
// Ghidra headless post-analysis script (run by analyzeHeadless via
// -postScript). Companion to DumpDecompiled.py: instead of decompiling
// every function's body (expensive -- a full DecompInterface pass per
// function), this walks Ghidra's function manager and writes out just
// each function's *signature* -- name, entry point, return type,
// parameters, and calling convention. That's enough evidence for a
// learner (or the LLM synthesizer) to get an inventory of what a binary
// exposes without paying for a full decompile, and it's useful as a fast
// first pass before deciding which specific functions are worth
// decompiling in full via DumpDecompiled.py.
//
// Written directly against Ghidra's documented Java scripting API
// (GhidraScript). Headless Ghidra compiles and runs .java scripts on the
// fly via its bundled script manager -- no separate `javac` step needed,
// and no dependency beyond the Ghidra install itself (see
// tools/ghidra_headless.py's module docstring for the Jython equivalent
// story). This has not been run against a real headless Ghidra instance
// in the environment this was authored in (no Ghidra install available)
// -- treat it as a reviewed draft the same way you would any new Ghidra
// script before trusting its output, per POLYGLOT_CORE_ADDITIONS.md.
//
// Expects exactly one script argument: the output file path.
// Invoked automatically by tools/ghidra_headless.py -- not meant to be
// run by hand, but nothing stops you from pointing analyzeHeadless at it
// directly if you want the raw Ghidra CLI experience:
//
//   analyzeHeadless <project_dir> <project_name> -import <binary> \
//       -postScript ExtractFunctionSignatures.java <output_file> \
//       -scriptPath <this dir>
//
// @category CTF-Tutor

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ExtractFunctionSignatures extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExtractFunctionSignatures.java: expected one arg (output file path)");
            return;
        }
        String outPath = args[0];

        FunctionManager functionManager = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();
        for (Function f : functionManager.getFunctions(true)) {
            functions.add(f);
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(outPath))) {
            writer.printf("# Function signatures: %s%n", currentProgram.getName());
            writer.printf("# %d function(s) found%n%n", functions.size());

            for (Function func : functions) {
                if (monitor.isCancelled()) {
                    break;
                }
                writer.println(formatSignature(func));
            }
        }
    }

    private String formatSignature(Function func) {
        StringBuilder sb = new StringBuilder();

        String returnType = func.getReturnType() != null
            ? func.getReturnType().getDisplayName()
            : "void";

        sb.append(returnType).append(' ').append(func.getName()).append('(');

        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            Parameter p = params[i];
            String paramType = p.getDataType() != null ? p.getDataType().getDisplayName() : "undefined";
            sb.append(paramType).append(' ').append(p.getName());
            if (i < params.length - 1) {
                sb.append(", ");
            }
        }
        sb.append(')');

        sb.append(" @ ").append(func.getEntryPoint());

        String convention = func.getCallingConventionName();
        if (convention != null && !convention.isEmpty()) {
            sb.append(" [").append(convention).append(']');
        }
        if (func.isThunk()) {
            sb.append(" (thunk)");
        }
        if (func.isExternal()) {
            sb.append(" (external)");
        }

        return sb.toString();
    }
}
