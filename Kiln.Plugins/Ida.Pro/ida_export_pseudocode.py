# -*- coding: utf-8 -*-
import json
import os
import sys

import idaapi
import idautils
import ida_hexrays
import idc

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

def main():
	if len(sys.argv) < 2:
		_usage()
		return

	out_path = sys.argv[1]
	name_filter = sys.argv[2] if len(sys.argv) > 2 else None

	if not _init_hexrays():
		print("Hex-Rays not available.")
		return

	items = []
	for ea in idautils.Functions():
		name = idc.get_name(ea)
		if not name:
			continue
		if name_filter and name_filter not in name:
			continue
		text = _decompile_to_text(ea)
		if not text:
			continue
		items.append({
			"ea": hex(ea),
			"name": name,
			"pseudocode": text,
		})

	result = {
		"count": len(items),
		"functions": items,
	}

	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(result, f, ensure_ascii=False, indent=2)

	print("Exported pseudocode:", len(items))

if __name__ == "__main__":
	main()
