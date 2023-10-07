#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import json
from .stack import get_from_tvm_list
from ..mytypes import Slice
from ..tlb import TlbSchemes

def DICTGET(code_slice, tvm):
	# TODO
	n = get_from_tvm_list(tvm.stack, 0)
	cell = get_from_tvm_list(tvm.stack, 0)
	key = get_from_tvm_list(tvm.stack, 0)
	
	tlb_schemes = TlbSchemes()
	tlb_schemes.load_schemes("/usr/src/ton/tl/generate/scheme/")
	
	#print("DICTGET:", cell, key, n)
	#hm = tlb_schemes.deser_hashmap_e(Slice(cell), n, "Cell")
	hm = dict()
	tlb_schemes.deser_hashmap(hm, Slice(cell), n, "Cell")
	#print("DICTGET hm:", hm)
	result = hm.get(key)
	print("DICTGET result:", result)
	if result != None:
		tvm.stack.append(result)
		tvm.stack.append(-1)
	else:
		tvm.stack.append(0)
	
	#hm2 = tlb_schemes.deserialize(cell, expected="HashmapE n Cell")
	#print("DICTGET hm2:", hm2)
	print("DICTGET cell:", json.dumps(cell.dump(), indent=4))
#end define

def DICTIGET(code_slice, tvm):
	# TODO
	DICTGET(code_slice, tvm)
#end define
