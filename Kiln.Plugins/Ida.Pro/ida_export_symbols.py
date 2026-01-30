# -*- coding: utf-8 -*-
import json
import os
import sys

import idaapi
import idautils
import ida_funcs
import idc

def _usage():
	print("Usage: ida_export_symbols.py <output-json> [min-ea] [max-ea]")

def _parse_ea(value, default):
	if value is None or value == "":
		return default
	value = value.strip()
	try:
		return int(value, 0)
	except Exception:
		return default

def _func_signature(ea):
	ctype = idc.get_type(ea)
	if ctype:
		return ctype
	name = idc.get_name(ea)
	return name + "()"

def main():
	if len(sys.argv) < 2:
		_usage()
		return

	out_path = sys.argv[1]
	min_ea = _parse_ea(sys.argv[2] if len(sys.argv) > 2 else None, idaapi.get_inf_structure().min_ea)
	max_ea = _parse_ea(sys.argv[3] if len(sys.argv) > 3 else None, idaapi.get_inf_structure().max_ea)

	items = []
	for ea in idautils.Functions(min_ea, max_ea):
		name = idc.get_name(ea)
		if not name:
			continue
		flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
		if flags == -1:
			continue
		end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
		seg = idc.get_segm_name(ea)
		items.append({
			"ea": hex(ea),
			"endEa": hex(end_ea) if end_ea != -1 else None,
			"name": name,
			"signature": _func_signature(ea),
			"segment": seg,
		})

	result = {
		"count": len(items),
		"symbols": items,
	}

	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(result, f, ensure_ascii=False, indent=2)

	print("Exported symbols:", len(items))

if __name__ == "__main__":
	main()
