# ExportFunctionIndex.py — VulneraBin Ghidra Script
# Exports function metadata with call graph, xrefs, and strings.
# Usage: analyzeHeadless ... -postScript ExportFunctionIndex.py <output_dir>
#
# Adapted from SurfaceStorm's ExportFunctionIndex.py

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import hashlib
import json
import os
import re


def normalize_code(c_code):
    """Normalize decompiled code for structural hashing."""
    if not c_code:
        return ""
    code = re.sub(r'//[^\n]*', '', c_code)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', code)
    code = re.sub(r'FUN_[0-9a-fA-F]+', 'FUN_NORM', code)
    code = re.sub(r'\b(local|param|uVar|iVar|lVar|bVar|cVar|sVar|unaff)_[0-9a-fA-F]+\b', r'\1_N', code)
    code = re.sub(r'\s+', ' ', code).strip()
    return code


def get_strings_for_function(program, func):
    """Get string references within a function."""
    strings = []
    body = func.getBody()
    ref_mgr = program.getReferenceManager()
    listing = program.getListing()

    for rng in body:
        addr = rng.getMinAddress()
        while addr is not None and addr.compareTo(rng.getMaxAddress()) <= 0:
            refs = ref_mgr.getReferencesFrom(addr)
            for ref in refs:
                to_addr = ref.getToAddress()
                data = listing.getDataAt(to_addr)
                if data and data.hasStringValue():
                    try:
                        val = data.getValue()
                        if val:
                            s = str(val)
                            if len(s) > 2:
                                strings.append(s[:200])
                    except:
                        pass
            instr = listing.getInstructionAt(addr)
            if instr:
                addr = instr.getMaxAddress().next()
            else:
                break

    return strings


def run():
    program = currentProgram
    args = getScriptArgs()

    if len(args) > 0:
        output_dir = args[0]
    else:
        output_dir = os.getcwd()

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    out_path = os.path.join(output_dir, "function_index.json")
    print("[VulneraBin] Exporting function index to: " + out_path)

    decomplib = DecompInterface()
    decomplib.openProgram(program)

    fm = program.getFunctionManager()
    listing = program.getListing()
    functions = []
    call_graph = {}

    for func in fm.getFunctions(True):
        entry = func.getEntryPoint()
        body = func.getBody()
        func_size = 0
        instr_count = 0

        for rng in body:
            func_size += rng.getLength()
            addr = rng.getMinAddress()
            while addr is not None and addr.compareTo(rng.getMaxAddress()) <= 0:
                instr = listing.getInstructionAt(addr)
                if instr:
                    instr_count += 1
                    addr = instr.getMaxAddress().next()
                else:
                    break

        # Call graph
        callees = []
        callers = []

        for cf in func.getCalledFunctions(ConsoleTaskMonitor()):
            callees.append(cf.getName())
        for cf in func.getCallingFunctions(ConsoleTaskMonitor()):
            callers.append(cf.getName())

        # Decompile for hash
        code_hash = ""
        monitor = ConsoleTaskMonitor()
        res = decomplib.decompileFunction(func, 60, monitor)
        if res.decompileCompleted():
            decomp = res.getDecompiledFunction()
            if decomp:
                c_code = decomp.getC()
                normalized = normalize_code(c_code)
                code_hash = hashlib.md5(normalized.encode('utf-8')).hexdigest()

        # String references
        strings = get_strings_for_function(program, func)

        func_info = {
            "name": func.getName(),
            "address": entry.toString(),
            "size": func_size,
            "instruction_count": instr_count,
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "is_exported": func.isGlobal(),
            "callees": callees,
            "callers": callers,
            "strings": strings[:50],
            "code_hash": code_hash,
        }
        functions.append(func_info)

        # Build call graph for chain analysis
        call_graph[entry.toString()] = callees

    result = {
        "binary": program.getName(),
        "format": program.getExecutableFormat(),
        "arch": str(program.getLanguage().getProcessor()),
        "address_size": program.getDefaultPointerSize(),
        "total_functions": len(functions),
        "functions": functions,
        "call_graph": call_graph,
    }

    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print("[VulneraBin] Exported %d functions" % len(functions))


if __name__ == "__main__":
    run()
