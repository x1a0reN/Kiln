# -*- coding: utf-8 -*-
import json
import os
import sys

import idaapi
import idautils
import ida_hexrays
import idc
import ida_funcs

def _usage():
	print("Usage: ida_export_pseudocode.py <output-json> [function-name-contains]")

def _init_hexrays():
	try:
		return ida_hexrays.init_hexrays_plugin()
	except Exception:
		return False

def _decompile_to_text(ea):
	try:
		cfunc = ida_hexrays.decompile(ea)
		if not cfunc:
			return None
		return str(cfunc)
	except Exception:
		return None

def _func_signature(ea):
	ctype = idc.get_type(ea)
	if ctype:
		return ctype
	name = idc.get_name(ea)
	return name + "()"

def _func_range(ea):
	end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
	if end_ea == -1:
		end_ea = ea
	size = max(0, end_ea - ea)
	return end_ea, size

def _disasm_func(ea, max_lines=400):
	lines = []
	for insn in idautils.FuncItems(ea):
		line = idc.generate_disasm_line(insn, 0)
		if line:
			lines.append(line)
		if len(lines) >= max_lines:
			break
	return "\n".join(lines), len(lines) >= max_lines

def main():
	out_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KILN_EXPORT_OUTPUT")
	name_filter = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("KILN_EXPORT_FILTER")
	if not out_path:
		_usage()
		return

	has_hexrays = _init_hexrays()

	items = []
	fallback_used = False
	for ea in idautils.Functions():
		name = idc.get_name(ea)
		if not name:
			continue
		if name_filter and name_filter not in name:
			continue
		end_ea, size = _func_range(ea)
		text = _decompile_to_text(ea) if has_hexrays else None
		truncated = False
		fallback = None
		if not text:
			text, truncated = _disasm_func(ea, 400)
			fallback = "disasm"
			fallback_used = True
			if not text:
				continue
		items.append({
			"ea": hex(ea),
			"endEa": hex(end_ea),
			"size": size,
			"name": name,
			"signature": _func_signature(ea),
			"pseudocode": text,
			"fallback": fallback,
			"truncated": truncated,
		})

	fallback_mode = None
	if not has_hexrays:
		fallback_mode = "disasm"
	elif fallback_used:
		fallback_mode = "mixed"

	result = {
		"count": len(items),
		"functions": items,
		"fallbackMode": fallback_mode,
	}

	out_dir = os.path.dirname(out_path)
	if out_dir:
		os.makedirs(out_dir, exist_ok=True)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(result, f, ensure_ascii=False, indent=2)

	print("Exported pseudocode:", len(items))

if __name__ == "__main__":
	main()
