#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from ..mytypes import Slice
from .stack import get_from_tvm_list
from .dict_get import DICTGET, DICTIGET

def DICTIGETJMP(code_slice, tvm):
	DICTIGET(code_slice, tvm)
	item = get_from_tvm_list(tvm.stack, 0)
	new_code_cell = get_from_tvm_list(tvm.stack, 0)
	if item == 0:
		return
	#end if
	
	new_code_slice = Slice(new_code_cell)
	tvm.run(new_code_slice)
	tvm.exit()
#end define

def DICTIGETJMPZ(code_slice, tvm):
	i = get_from_tvm_list(tvm.stack, 2, remove=False)
	DICTIGET(code_slice, tvm)
	item = get_from_tvm_list(tvm.stack, 0)
	new_code_cell = get_from_tvm_list(tvm.stack, 0)
	if item == 0:
		return i
	#end if
	
	new_code_slice = Slice(new_code_cell)
	tvm.run(new_code_slice)
	tvm.exit()
#end define
