# -*- coding: utf-8 -*-
import os
import runpy
import sys

import idaapi
import idc

def _usage():
	print("Usage: IdaAutoLoadSymbols.py <ida_with_struct_py3.py> <script.json> <il2cpp.h>")

def main():
	symbol_script = None
	script_json = None
	il2cpp_header = None
	if len(sys.argv) >= 4:
		symbol_script = sys.argv[1]
		script_json = sys.argv[2]
		il2cpp_header = sys.argv[3]
	else:
		symbol_script = os.environ.get("KILN_SYMBOL_SCRIPT")
		script_json = os.environ.get("KILN_SCRIPT_JSON")
		il2cpp_header = os.environ.get("KILN_IL2CPP_HEADER")

	if not symbol_script or not script_json or not il2cpp_header:
		_usage()
		return

	if not os.path.isfile(symbol_script):
		print("Symbol script not found:", symbol_script)
		return
	if not os.path.isfile(script_json):
		print("script.json not found:", script_json)
		return
	if not os.path.isfile(il2cpp_header):
		print("il2cpp.h not found:", il2cpp_header)
		return

	print("Waiting for IDA auto-analysis...")
	try:
		idc.auto_wait()
	except Exception as ex:
		print("auto_wait failed:", ex)

	orig_ask_file = idaapi.ask_file
	def _ask_file(save, mask, prompt):
		if mask and mask.endswith(".json"):
			return script_json
		if mask and mask.endswith(".h"):
			return il2cpp_header
		return script_json

	idaapi.ask_file = _ask_file
	try:
		runpy.run_path(symbol_script, run_name="__main__")
	finally:
		idaapi.ask_file = orig_ask_file

if __name__ == "__main__":
	main()
