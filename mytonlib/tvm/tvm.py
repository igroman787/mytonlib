#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from bitstring import BitStream
from ..mytypes import Slice, Cell, Dict
from .instructions import init_instructions




class TVM:
	def __init__(self, code_cell, data_cell, message_cell):
		self.working = True
		self.stack = list()
		self.control_registers = list()
		self.code_slice = Slice(code_cell)
		self.cp = 0
		self.gas_limits = None
		self.library_context = None
		self.instructions = list()
		init_instructions(self.instructions)
		
		message_slice = Slice(message_cell)
		self._init_stack(447573316514, 1000, message_cell, message_slice, -1)
		self._init_control_registers(data_cell)
	#end define
	
	def _init_stack(self, smc_balance, message_balance, message, message_body, selector):
		self.stack.append(smc_balance)			# Баланс смартконтракта (в нанотон)
		self.stack.append(message_balance)		# Баланс входящего сообщения
		self.stack.append(message)				# Входящее сообщение передается как ячейка, содержащая сериализованное значение типа Message X, где X — тип тела сообщения
		self.stack.append(message_body)			# Тело входящего сообщения, равное значению поля body m, передается как срез ячейки
		self.stack.append(selector)				# Селектор функции s, целое число: 0 для tx, вызванного внутренними сообщениями, -1 для внешних и т. д.
	#end define
	
	def _init_control_registers(self, data_cell):
		unixtime = 1683895184 - 1
		block_lt = None
		trans_lt = None
		random_seed = None
		remaining_balance_tuple = None
		internal_address_slice = None
		global_configuration = None
		c7 = (None, None, None, unixtime, block_lt, trans_lt, random_seed, remaining_balance_tuple, internal_address_slice, global_configuration)
		self.control_registers.append(c7)			# c7
		self.control_registers.append(None)			# c6
		self.control_registers.append(None)			# c5
		self.control_registers.append(data_cell)	# c4
		self.control_registers.append(None)			# c3
		self.control_registers.append(None)			# c2
		self.control_registers.append(None)			# c1
		self.control_registers.append(None)			# c0
	#end define
	
	def run(self, code_slice=None):
		if code_slice is None:
			code_slice = self.code_slice
		bit_stream = code_slice.bit_stream
		while bit_stream.pos < bit_stream.len and self.working is True:
			self._do(code_slice)
	#end define
	
	def exit(self, exit_code=0):
		self.working = False
	#end define
	
	def _do(self, code_slice):
		instruction = self._find_instruction(code_slice)
		if instruction.action is None:
			raise Exception(f"TVM run error: Action is none")
		instruction.action(code_slice, self)
		print(f"_do: {instruction.name}, stack: {self.stack}")
	#end define
	
	def _find_instruction(self, code_slice):
		buff = code_slice.show_bits(16)
		for instruction in self.instructions:
			prefix_len = len(instruction.prefix_bit)
			buff_prefix = buff[0:prefix_len]
			if buff_prefix == instruction.prefix_bit:
				code_slice.read(prefix_len)
				return instruction
		prefix = BitStream(bin=buff).hex
		raise Exception(f"find_instruction error: Instruction with prefix: `{prefix}` ({buff}) not found. code_slice: {code_slice.show()}")
	#end define
#end class
