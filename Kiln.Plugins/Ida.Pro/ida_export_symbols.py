# -*- coding: utf-8 -*-
import json
import os
import sys

import idaapi
import idautils
import ida_funcs
import idc
import ida_ida

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

def _get_min_max_ea():
	try:
		inf = idaapi.get_inf_structure()
		return inf.min_ea, inf.max_ea
	except Exception:
		try:
			return ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
		except Exception:
			return 0, 0

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

def _collect_calls(func_ea):
	calls = set()
	for insn in idautils.FuncItems(func_ea):
		mnem = idc.print_insn_mnem(insn).lower()
		if not mnem.startswith("call"):
			continue
		for cref in idautils.CodeRefsFrom(insn, 0):
			callee = ida_funcs.get_func(cref)
			calls.add(callee.start_ea if callee else cref)
	return calls

def _collect_callers(func_ea):
	callers = set()
	for cref in idautils.CodeRefsTo(func_ea, 0):
		caller = ida_funcs.get_func(cref)
		if caller:
			callers.add(caller.start_ea)
	return callers

def _collect_strings():
	strings = []
	for s in idautils.Strings():
		value = str(s)
		ea = s.ea
		refs = []
		for ref in idautils.DataRefsTo(ea):
			func = ida_funcs.get_func(ref)
			if func:
				refs.append({
					"funcEa": hex(func.start_ea),
					"funcName": idc.get_name(func.start_ea),
					"refEa": hex(ref),
				})
		strings.append({
			"ea": hex(ea),
			"value": value,
			"length": len(value),
			"refs": refs,
			"refCount": len(refs),
		})
	return strings

def main():
	out_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KILN_EXPORT_OUTPUT")
	min_env = os.environ.get("KILN_EXPORT_MIN_EA")
	max_env = os.environ.get("KILN_EXPORT_MAX_EA")
	min_arg = sys.argv[2] if len(sys.argv) > 2 else min_env
	max_arg = sys.argv[3] if len(sys.argv) > 3 else max_env
	if not out_path:
		_usage()
		return

	default_min, default_max = _get_min_max_ea()
	min_ea = _parse_ea(min_arg, default_min)
	max_ea = _parse_ea(max_arg, default_max)

	items = []
	for ea in idautils.Functions(min_ea, max_ea):
		name = idc.get_name(ea)
		if not name:
			continue
		flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
		if flags == -1:
			continue
		end_ea, size = _func_range(ea)
		seg = idc.get_segm_name(ea)
		calls = sorted(_collect_calls(ea))
		callers = sorted(_collect_callers(ea))
		items.append({
			"ea": hex(ea),
			"endEa": hex(end_ea) if end_ea != -1 else None,
			"size": size,
			"name": name,
			"signature": _func_signature(ea),
			"segment": seg,
			"calls": [hex(x) for x in calls],
			"callers": [hex(x) for x in callers],
		})

	result = {
		"count": len(items),
		"symbols": items,
		"imageBase": hex(idaapi.get_imagebase()),
	}

	output_dir = os.path.dirname(out_path)
	if output_dir:
		os.makedirs(output_dir, exist_ok=True)

	strings_path = os.path.join(output_dir, "strings.json")
	strings = _collect_strings()
	with open(strings_path, "w", encoding="utf-8") as f:
		json.dump({
			"count": len(strings),
			"strings": strings,
		}, f, ensure_ascii=False, indent=2)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(result, f, ensure_ascii=False, indent=2)

	print("Exported symbols:", len(items))

if __name__ == "__main__":
	main()
