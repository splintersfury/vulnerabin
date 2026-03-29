# ExportDecompiled.py — VulneraBin Ghidra Script
# Exports decompiled C code for all functions in the binary.
# Usage: analyzeHeadless <project> <process> -import <file> -postScript ExportDecompiled.py <output_dir>
#
# Adapted from SurfaceStorm's ExportDecompiled.py

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os


def run():
    program = currentProgram
    decomplib = DecompInterface()
    decomplib.openProgram(program)

    args = getScriptArgs()
    if len(args) > 0:
        out_dir = args[0]
    else:
        out_dir = os.getcwd()

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    out_path = os.path.join(out_dir, "decompiled.c")
    print("[VulneraBin] Exporting decompiled code to: " + out_path)

    fm = program.getFunctionManager()
    funcs = fm.getFunctions(True)
    count = 0
    errors = 0

    try:
        with open(out_path, "w") as f:
            f.write("// Decompiled by Ghidra — VulneraBin\n")
            f.write("// Binary: " + program.getName() + "\n")
            f.write("// Format: " + program.getExecutableFormat() + "\n")
            f.write("// Arch: " + str(program.getLanguage().getProcessor()) + "\n\n")

            for func in funcs:
                monitor = ConsoleTaskMonitor()
                res = decomplib.decompileFunction(func, 60, monitor)
                if res.decompileCompleted():
                    decomp = res.getDecompiledFunction()
                    if decomp:
                        c_code = decomp.getC()
                        f.write("// FUNCTION_START: " + func.getName() + " @ " + func.getEntryPoint().toString() + "\n")
                        f.write(c_code)
                        f.write("\n// FUNCTION_END\n\n")
                        count += 1
                else:
                    errors += 1

        print("[VulneraBin] Exported %d functions (%d errors)" % (count, errors))

    except Exception as e:
        print("[VulneraBin] Error: " + str(e))


if __name__ == "__main__":
    run()
