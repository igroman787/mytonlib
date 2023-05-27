#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from .stack import get_from_tvm_list


def PUSHINT_4(code_slice, tvm):
	# WTF
	# Pushes integer `x` into the stack. `-5 <= x <= 10`. Here `i` equals four lower-order bits of `x` (`i=x mod 16`).
	buff = code_slice.read(4)
	if buff.uint == 15:
		tvm.stack.append(-1)
	else:
		tvm.stack.append(buff.uint)
#end define

def PUSHINT_8(code_slice, tvm):
	buff = code_slice.read(8)
	tvm.stack.append(buff.int)
#end define

def PUSHINT_16(code_slice, tvm):
	buff = code_slice.read(16)
	tvm.stack.append(buff.int)
#end define

def PUSHINT_LONG(code_slice, tvm):
	buff = code_slice.read(5)
	n = 8 * buff.uint + 19
	buff = code_slice.read(n)
	tvm.stack.append(buff.int)
#end define

def PUSHPOW2(code_slice, tvm):
	buff = code_slice.read(8)
	result = 2 ** (buff.uint + 1)
	tvm.stack.append(result)
#end define

def PUSHPOW2DEC(code_slice, tvm):
	buff = code_slice.read(8)
	result = 2 ** (buff.uint + 1) - 1
	tvm.stack.append(result)
#end define

def PUSHNEGPOW2(code_slice, tvm):
	buff = code_slice.read(8)
	result = -2 ** (buff.uint + 1)
	tvm.stack.append(result)
#end define