#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from bitstring import BitStream
from ..mytypes import Slice, Cell, Dict
from .instructions import init_instructions
from .stack import get_from_tvm_list




class TVM:
	#def __init__(self, accoun_state, message_balance, message_cell, selector):
	def __init__(self, **kwargs):
		kwargs = Dict(kwargs)
		smc_balance = kwargs.accoun_state.storage.balance.grams.amount
		code_cell = kwargs.accoun_state.storage.state.code
		data_cell = kwargs.accoun_state.storage.state.data
	
		self.working = True
		self.stack = list()
		self.control_registers = list()
		self.code_slice = Slice(code_cell)
		self.cp = 0
		self.gas_limits = None
		self.library_context = None
		self.instructions = list()
		init_instructions(self.instructions)
		
		# check types
		if kwargs.params == None:
			kwargs.params = list()
		if type(kwargs.params) != list:
			raise Exception("TVM __init__ error: params must be list")
		#end if
		
		if kwargs.selector > 0:
			# Run get method
			self.stack += kwargs.params
			self.stack.append(kwargs.selector)
		elif kwargs.selector == 0:
			# Internal message
			self._init_stack_as_message(smc_balance, kwargs.message_balance, kwargs.message_cell, kwargs.selector)
		elif kwargs.selector == -1:
			# External message
			_init_stack_as_message(smc_balance, 0, kwargs.message_cell, kwargs.selector)
		elif kwargs.selector == -2:
			# Tick tock
			raise Exception("TVM error: Tick tock method is not implemented")
		elif kwargs.selector == -3:
			# Split prepare
			raise Exception("TVM error: Split prepare method is not implemented")
		elif kwargs.selector == -4:
			# Merge install
			raise Exception("TVM error: Merge install method is not implemented")
		#end if
		
		self._init_control_registers(data_cell)
	#end define
	
	def _init_stack_as_message(self, smc_balance, message_balance, message, selector):
		message_body = Slice(message)
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
		c5 = Cell()
		self.control_registers.append(c7)			# c7
		self.control_registers.append(None)			# c6
		self.control_registers.append(c5)			# c5
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
		c4 = get_from_tvm_list(self.control_registers, 4, remove=False)
		c5 = get_from_tvm_list(self.control_registers, 5, remove=False)
		return self.stack
	#end define
	
	def exit(self, exit_code=0):
		self.working = False
	#end define
	
	def _do(self, code_slice):
		instruction = self._find_instruction(code_slice)
		if instruction.action is None:
			raise Exception(f"TVM run error: Action is none")
		print(f"_do: {instruction.name}")
		instruction.action(code_slice, self)
		print(f"stack: {self.stack}")
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
