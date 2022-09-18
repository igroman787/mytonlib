#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from bitstring import BitStream # pip3 install bitstring


class Cell:
	def __init__(self):
		self.special = None
		self.bits_sz = None
		self.level_mask = None
		self.data = None
		self.refs = None
	#end define
	
	def __str__(self):
		data_hex = None
		if self.data is not None:
			data_hex = self.data.hex()
		result = f"<Cell {self.bits_sz}:{data_hex}={len(self.refs)}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
#end class

class Slice(Cell):
	def __init__(self, cell):
		self.special = cell.special
		self.bits_sz = cell.bits_sz
		self.level_mask = cell.level_mask
		self.bit_stream = BitStream(cell.data)
		self.refs = cell.refs
		self.used_refs_index = 0
	#end define
	
	def read_cell(self):
		"""
		Read next cell from refs
		"""
		result = self.refs[self.used_refs_index]
		self.used_refs_index += 1
		return result
#end class

def cells2dict(cells, to_json=False):
	result = dict()
	for i in range(len(cells)):
		cell = cells[i]
		result[i] = cell2dict(cell, to_json=to_json)
	return result
#end define

def cell2dict(cell, to_json=False):
	data = cell.data
	if to_json is True:
		data = data.hex()
	result = dict()
	result["special"] = cell.special
	result["bits_sz"] = cell.bits_sz
	result["level"] = cell.level
	result["data"] = data
	result["refs"] = cells2dict(cell.refs, to_json=to_json)
	return result
#end define

class Dict(dict):
	def to_class(self):
		for key, value in self.items():
			setattr(self, key, value)
		#end for
	#end define
	
	def to_dict(self):
		for key, value in self.items():
			self[key] = getattr(self, key)
		#end for
#end class
