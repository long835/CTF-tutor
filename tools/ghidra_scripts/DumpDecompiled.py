# DumpDecompiled.py
#
# Ghidra headless post-analysis script (Jython, run by analyzeHeadless via
# -postScript). Decompiles every function Ghidra found and writes the
# results to a plain-text file, so a wrapper process (see
# tools/ghidra_headless.py) can read it back without needing to speak
# Ghidra's Java API itself.
#
# Expects exactly one script argument: the output file path.
# Invoked automatically by tools/ghidra_headless.py -- not meant to be run
# by hand, but nothing stops you from pointing analyzeHeadless at it
# directly if you want the raw Ghidra CLI experience:
#
#   analyzeHeadless <project_dir> <project_name> -import <binary> \
#       -postScript DumpDecompiled.py <output_file> -scriptPath <this dir>
#
# @category CTF-Tutor

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def run():
    args = getScriptArgs()
    if len(args) < 1:
        print("DumpDecompiled.py: expected one arg (output file path)")
        return
    out_path = args[0]

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    function_manager = currentProgram.getFunctionManager()
    functions = list(function_manager.getFunctions(True))

    with open(out_path, "w") as f:
        f.write("# Decompiled: %s\n" % currentProgram.getName())
        f.write("# %d function(s) found\n\n" % len(functions))
        for func in functions:
            f.write("// ---- %s @ %s ----\n" % (func.getName(), func.getEntryPoint()))
            result = decompiler.decompileFunction(func, 30, monitor)
            if result.decompileCompleted():
                f.write(result.getDecompiledFunction().getC())
            else:
                f.write("// [decompilation failed: %s]\n" % result.getErrorMessage())
            f.write("\n\n")

    decompiler.dispose()


run()
