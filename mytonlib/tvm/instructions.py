#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from bitstring import BitStream
from .stack import get_from_tvm_list, swap_items_in_tvm_list
from ..mytypes import Slice, Cell
from .app_crypto import *
from .const_int import *

class Instruction:
	def __init__(self, **kwargs):
		self.action = kwargs.get("action")
		self.name = self.action.__name__
		if "prefix_bit" in kwargs:
			self.prefix_bit = kwargs.get("prefix_bit")
		elif "prefix" in kwargs:
			self.prefix = kwargs.get("prefix")
			self.prefix_bit = BitStream(hex=self.prefix).bin
	#end define
#end class



def NOP(code_slice, tvm):
	pass
#end define

def SWAP(code_slice, tvm):
	swap_items_in_tvm_list(tvm.stack, 0, 1)
#end define

def XCHG_0I(code_slice, tvm):
	buff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 0, buff.uint)
#end define

def XCHG_IJ(code_slice, tvm):
	ibuff = code_slice.read(4)
	jbuff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, ibuff.uint, jbuff.uint)
#end define

def XCHG_0I_LONG(code_slice, tvm):
	buff = code_slice.read(8)
	swap_items_in_tvm_list(tvm.stack, 0, buff.uint)
#end define

def XCHG_1I(code_slice, tvm):
	buff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 1, buff.uint)
#end define

def XCHG_2I(code_slice, tvm):
	buff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 2, buff.uint)
#end define

def PUSH(code_slice, tvm):
	buff = code_slice.read(4)
	item = get_from_tvm_list(tvm.stack, buff.uint, remove=False)
	tvm.stack.append(item)
#end define

def POP(code_slice, tvm):
	buff = code_slice.read(4)
	item = get_from_tvm_list(tvm.stack, buff.uint)
#end define



def XCHG3(code_slice, tvm):
	# Equivalent to `s2 s[i] XCHG` `s1 s[j] XCHG` `s[k] XCHG0`.
	#ibuff = code_slice.read(4)
	#jbuff = code_slice.read(4)
	#kbuff = code_slice.read(4)
	#swap_items_in_tvm_list(tvm.stack, 2, ibuff.uint)
	#swap_items_in_tvm_list(tvm.stack, 1, jbuff.uint)
	#swap_items_in_tvm_list(tvm.stack, 0, kbuff.uint)
	XCHG_2I(code_slice, tvm)
	XCHG_1I(code_slice, tvm)
	XCHG_0I(code_slice, tvm)
#end define

def XCHG2(code_slice, tvm):
	# Equivalent to `s1 s[i] XCHG` `s[j] XCHG0`.
	#ibuff = code_slice.read(4)
	#jbuff = code_slice.read(4)
	#swap_items_in_tvm_list(tvm.stack, 1, ibuff.uint)
	#swap_items_in_tvm_list(tvm.stack, 0, jbuff.uint)
	XCHG_1I(code_slice, tvm)
	XCHG_0I(code_slice, tvm)
#end define

def XCPU(code_slice, tvm):
	# Equivalent to `s[i] XCHG0` `s[j] PUSH`.
	#ibuff = code_slice.read(4)
	#jbuff = code_slice.read(4)
	#swap_items_in_tvm_list(tvm.stack, 0, ibuff.uint)
	#item = get_from_tvm_list(tvm.stack, jbuff.uint, remove=False)
	#tvm.stack.append(item)
	XCHG_0I(code_slice, tvm)
	PUSH(code_slice, tvm)
#end define

def PUXC(code_slice, tvm):
	# Equivalent to `s[i] PUSH` `SWAP` `s[j] XCHG0`.
	#ibuff = code_slice.read(4)
	#jbuff = code_slice.read(4)
	#item = get_from_tvm_list(tvm.stack, ibuff.uint, remove=False)
	#tvm.stack.append(item)
	#swap_items_in_tvm_list(tvm.stack, 0, 1)
	#swap_items_in_tvm_list(tvm.stack, 0, jbuff.uint)
	PUSH(code_slice, tvm)
	SWAP(code_slice, tvm)
	XCHG_0I(code_slice, tvm)
#end define

def PUSH2(code_slice, tvm):
	# Equivalent to `s[i] PUSH` `s[j+1] PUSH`.
	ibuff = code_slice.read(4)
	jbuff = code_slice.read(4)
	item = get_from_tvm_list(tvm.stack, ibuff.uint, remove=False)
	tvm.stack.append(item)
	item = get_from_tvm_list(tvm.stack, jbuff.uint+1, remove=False)
	tvm.stack.append(item)
#end define

def XC2PU(code_slice, tvm):
	# Equivalent to `s[i] s[j] XCHG2` `s[k] PUSH`.
	#ibuff = code_slice.read(4)
	#jbuff = code_slice.read(4)
	#kbuff = code_slice.read(4)
	#swap_items_in_tvm_list(tvm.stack, 1, ibuff.uint)
	#swap_items_in_tvm_list(tvm.stack, 0, jbuff.uint)
	#item = get_from_tvm_list(tvm.stack, kbuff.uint, remove=False)
	#tvm.stack.append(item)
	XCHG2(code_slice, tvm)
	PUSH(code_slice, tvm)
#end define


def XCPUXC(code_slice, tvm):
	# Equivalent to `s1 s[i] XCHG` `s[j] s[k-1] PUXC`.
	XCHG_1I(code_slice, tvm)
	PUSH(code_slice, tvm)
	SWAP(code_slice, tvm)
	kbuff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 0, kbuff.uint-1)
#end define

def XCPU2(code_slice, tvm):
	# Equivalent to `s[i] XCHG0` `s[j] s[k] PUSH2`.
	XCHG_0I(code_slice, tvm)
	PUSH2(code_slice, tvm)
#end define

def PUXC2(code_slice, tvm):
	# Equivalent to `s[i] PUSH` `s2 XCHG0` `s[j] s[k] XCHG2`.
	PUSH(code_slice, tvm)
	swap_items_in_tvm_list(tvm.stack, 0, 2)
	XCHG2(code_slice, tvm)
#end define

def PUXCPU(code_slice, tvm):
	# Equivalent to `s[i] s[j-1] PUXC` `s[k] PUSH`.
	PUSH(code_slice, tvm)
	SWAP(code_slice, tvm)
	jbuff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 0, jbuff.uint-1)
	PUSH(code_slice, tvm)
#end define

def PU2XC(code_slice, tvm):
	# Equivalent to `s[i] PUSH` `SWAP` `s[j] s[k-1] PUXC`.
	PUSH(code_slice, tvm)
	SWAP(code_slice, tvm)
	jbuff = code_slice.read(4)
	swap_items_in_tvm_list(tvm.stack, 0, jbuff.uint-1)
#end define

def PUSH3(code_slice, tvm):
	# Equivalent to `s[i] PUSH` `s[j+1] s[k+1] PUSH2`.
	PUSH(code_slice, tvm)
	jbuff = code_slice.read(4)
	kbuff = code_slice.read(4)
	item = get_from_tvm_list(tvm.stack, jbuff.uint+1, remove=False)
	tvm.stack.append(item)
	item = get_from_tvm_list(tvm.stack, kbuff.uint+2, remove=False)
	tvm.stack.append(item)
#end define













def PUSHCONT_SHORT(code_slice, tvm):
	buff = code_slice.read(4)
	buff = code_slice.read_bytes(buff.uint)
	tvm.stack.append(buff)
#end define

def INC(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	result = item + 1
	tvm.stack.append(result)
#end define

def DEC(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	result = item - 1
	tvm.stack.append(result)
#end define

def AND(code_slice, tvm):
	x = get_from_tvm_list(tvm.stack, 0)
	y = get_from_tvm_list(tvm.stack, 0)
	result = x & y
	tvm.stack.append(result)
#end define

def OR(code_slice, tvm):
	x = get_from_tvm_list(tvm.stack, 0)
	y = get_from_tvm_list(tvm.stack, 0)
	result = x | y
	tvm.stack.append(result)
#end define

def XOR(code_slice, tvm):
	x = get_from_tvm_list(tvm.stack, 0)
	y = get_from_tvm_list(tvm.stack, 0)
	result = x ^ y
	tvm.stack.append(result)
#end define

def NOT(code_slice, tvm):
	x = get_from_tvm_list(tvm.stack, 0)
	result = ~x
	tvm.stack.append(result)
#end define

def SGN(code_slice, tvm):
	x = get_from_tvm_list(tvm.stack, 0)
	if x > 0:
		result = 1
	elif x == 0:
		result = 0
	else:
		result = -1
	tvm.stack.append(result)
#end define

def LESS(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x < y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def EQUAL(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x == y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def LEQ(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x <= y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def GREATER(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x > y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def NEQ(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x != y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def GEQ(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x >= y:
		result = -1
	else:
		result = 0
	tvm.stack.append(result)
#end define

def CMP(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	if x > y:
		result = 1
	elif x == y:
		result = 0
	else:
		result = -1
	tvm.stack.append(result)
#end define

def CTOS(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Cell:
		raise Exception(f"CTOS error: item is not cell")
	result = Slice(item)
	tvm.stack.append(result)
#end define

def ENDS(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"ENDS error: item is not slice")
	if item.bit_stream.pos != item.bit_stream.len:
		tvm.exit(34)
#end define

def LDI(code_slice, tvm):
	buff = code_slice.read(8)
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"LDI error: item is not slice")
	n = buff.uint + 1
	buff = item.read(n)
	result = buff.int
	tvm.stack.append(result)
	tvm.stack.append(item)
#end define

def LDU(code_slice, tvm):
	buff = code_slice.read(8)
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"LDU error: item is not slice")
	n = buff.uint + 1
	buff = item.read(n)
	result = buff.uint
	tvm.stack.append(result)
	tvm.stack.append(item)
#end define

def PLDI(code_slice, tvm):
	buff = code_slice.read(8)
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"PLDI error: item is not slice")
	n = buff.uint + 1
	buff = item.read(n)
	result = buff.int
	tvm.stack.append(result)
#end define

def PLDU(code_slice, tvm):
	buff = code_slice.read(8)
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"PLDU error: item is not slice")
	n = buff.uint + 1
	buff = item.read(n)
	result = buff.uint
	tvm.stack.append(result)
#end define

def LDSLICEX(code_slice, tvm):
	read_bits_len = get_from_tvm_list(tvm.stack, 0)
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception(f"LDSLICEX error: item is not slice")
	buff = item.read(read_bits_len)
	new_cell = Cell(buff.bytes)
	new_slice = Slice(new_cell)
	tvm.stack.append(new_slice)
	tvm.stack.append(item)
#end define

def IFNOTRET(code_slice, tvm):
	buff = get_from_tvm_list(tvm.stack, 0)
	if buff == 0:
		raise Exception("IFNOTRET return")
#end define

def IFJMP(code_slice, tvm):
	code_bytes = get_from_tvm_list(tvm.stack, 0)
	item = get_from_tvm_list(tvm.stack, 0)
	if item == 0:
		return 
	#end if
	
	new_code_cell = Cell(code_bytes)
	new_code_slice = Slice(new_code_cell)
	tvm.run(new_code_slice)
	tvm.exit()
#end define

def CONDSEL(code_slice, tvm):
	y = get_from_tvm_list(tvm.stack, 0)
	x = get_from_tvm_list(tvm.stack, 0)
	f = get_from_tvm_list(tvm.stack, 0)
	if f != 0:
		result = x
	else:
		result = y
	tvm.stack.append(result)
#end define

def PUSHCTR(code_slice, tvm):
	buff = code_slice.read(4)
	result = get_from_tvm_list(tvm.control_registers, buff.uint)
	tvm.stack.append(result)
#end define

def THROWIF_SHORT(code_slice, tvm):
	buff = code_slice.read(6)
	f = get_from_tvm_list(tvm.stack, 0)
	if f != 0:
		raise Exception(f"THROWIF_SHORT exception {buff.uint}")
#end define

def THROWIFNOT_SHORT(code_slice, tvm):
	buff = code_slice.read(6)
	f = get_from_tvm_list(tvm.stack, 0)
	#if f == 0:
		#raise Exception(f"THROWIFNOT_SHORT exception {buff.uint}")
#end define

def GETPARAM(code_slice, tvm):
	с7 = get_from_tvm_list(tvm.control_registers, 7, remove=False)
	buff = code_slice.read(4)
	result = с7[buff.uint]
	print(f"GETPARAM {buff.uint} -> {result}")
	tvm.stack.append(result)
#end define

def SETCP0(code_slice, tvm):
	pass
#end define

def init_instructions(instructions):
	instructions.append(Instruction(prefix = '00', action = NOP))
	instructions.append(Instruction(prefix = '01', action = SWAP))
	instructions.append(Instruction(prefix = '0', action = XCHG_0I))
	instructions.append(Instruction(prefix = '10', action = XCHG_IJ))
	instructions.append(Instruction(prefix = '11', action = XCHG_0I_LONG))
	instructions.append(Instruction(prefix = '1', action = XCHG_1I))
	instructions.append(Instruction(prefix = '2', action = PUSH))
	instructions.append(Instruction(prefix = '3', action = POP))
	
	instructions.append(Instruction(prefix = '4', action = XCHG3))
	instructions.append(Instruction(prefix = '50', action = XCHG2))
	instructions.append(Instruction(prefix = '51', action = XCPU))
	instructions.append(Instruction(prefix = '52', action = PUXC))
	instructions.append(Instruction(prefix = '53', action = PUSH2))
	instructions.append(Instruction(prefix = '540', action = XCHG3))
	instructions.append(Instruction(prefix = '541', action = XC2PU))
	instructions.append(Instruction(prefix = '542', action = XCPUXC))
	instructions.append(Instruction(prefix = '543', action = XCPU2))
	instructions.append(Instruction(prefix = '544', action = PUXC2))
	instructions.append(Instruction(prefix = '545', action = PUXCPU))
	instructions.append(Instruction(prefix = '546', action = PU2XC))
	instructions.append(Instruction(prefix = '547', action = PUSH3))
	
	# const_int
	instructions.append(Instruction(prefix = '7', action = PUSHINT_4))
	instructions.append(Instruction(prefix = '80', action = PUSHINT_8))
	instructions.append(Instruction(prefix = '81', action = PUSHINT_16))
	instructions.append(Instruction(prefix = '82', action = PUSHINT_LONG))
	instructions.append(Instruction(prefix = '83', action = PUSHPOW2))
	instructions.append(Instruction(prefix = '84', action = PUSHPOW2DEC))
	instructions.append(Instruction(prefix = '85', action = PUSHNEGPOW2))
	
	# const_data
	instructions.append(Instruction(prefix = '9', action = PUSHCONT_SHORT))
	
	# arithm_basic
	instructions.append(Instruction(prefix = 'A4', action = INC))
	instructions.append(Instruction(prefix = 'A5', action = DEC))
	
	# arithm_logical
	instructions.append(Instruction(prefix = 'B0', action = AND))
	instructions.append(Instruction(prefix = 'B1', action = OR))
	instructions.append(Instruction(prefix = 'B2', action = XOR))
	instructions.append(Instruction(prefix = 'B3', action = NOT))
	instructions.append(Instruction(prefix = 'B8', action = SGN))
	instructions.append(Instruction(prefix = 'B9', action = LESS))
	instructions.append(Instruction(prefix = 'BA', action = EQUAL))
	instructions.append(Instruction(prefix = 'BB', action = LEQ))
	instructions.append(Instruction(prefix = 'BC', action = GREATER))
	instructions.append(Instruction(prefix = 'BD', action = NEQ))
	instructions.append(Instruction(prefix = 'BE', action = GEQ))
	instructions.append(Instruction(prefix = 'BC', action = CMP))
	instructions.append(Instruction(prefix = 'D0', action = CTOS))
	instructions.append(Instruction(prefix = 'D1', action = ENDS))
	instructions.append(Instruction(prefix = 'D2', action = LDI))
	instructions.append(Instruction(prefix = 'D3', action = LDU))
	instructions.append(Instruction(prefix = 'D70A', action = PLDI))
	instructions.append(Instruction(prefix = 'D70B', action = PLDU))
	instructions.append(Instruction(prefix = 'D718', action = LDSLICEX))
	instructions.append(Instruction(prefix = 'DD', action = IFNOTRET))
	instructions.append(Instruction(prefix = 'E0', action = IFJMP))
	instructions.append(Instruction(prefix = 'E304', action = CONDSEL))
	instructions.append(Instruction(prefix = 'ED4', action = PUSHCTR))
	instructions.append(Instruction(prefix = 'F2_', prefix_bit="1111001001", action = THROWIF_SHORT))
	instructions.append(Instruction(prefix = 'F2_', prefix_bit="1111001010", action = THROWIFNOT_SHORT))
	instructions.append(Instruction(prefix = 'F82', action = GETPARAM))
	instructions.append(Instruction(prefix = 'F900', action = HASHCU))
	instructions.append(Instruction(prefix = 'F901', action = HASHSU))
	instructions.append(Instruction(prefix = 'F902', action = SHA256U))
	instructions.append(Instruction(prefix = 'F910', action = CHKSIGNU))
	instructions.append(Instruction(prefix = 'F911', action = CHKSIGNS))
	instructions.append(Instruction(prefix = 'FF00', action = SETCP0))
#end define
