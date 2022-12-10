#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from bitstring import BitStream # pip3 install bitstring


def int_be(data):
	return int.from_bytes(data, byteorder="big", signed=True)
#end define

def uint_be(data):
	return int.from_bytes(data, byteorder="big", signed=False)
#end define

def int_le(data):
	return int.from_bytes(data, byteorder="little", signed=True)
#end define

def uint_le(data):
	return int.from_bytes(data, byteorder="little", signed=False)
#end define

class Cell:
	def __init__(self):
		self.special = False
		self.bits_sz = 0
		self.level = 0
		self.data = bytes()
		self.refs = list()
		self.index = None
	#end define
	
	def __eq__(self, cell):
		return self.data == cell.data
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
	
	def add_ref(self, cell):
		self.refs.append(cell)
	#end define
	
	def copy(self, cell):
		self.special = cell.special
		self.bits_sz = cell.bits_sz
		self.level = cell.level
		self.data = cell.data
		self.refs = cell.refs
	#end define
#end class

class Slice(Cell):
	def __init__(self, cell):
		self.special = cell.special
		self.bits_sz = cell.bits_sz
		self.level = cell.level
		self.bit_stream = BitStream(cell.data)
		self.refs = cell.refs
		self.used_refs_index = 0
	#end define
	
	def read_ref(self):
		result = self.refs[self.used_refs_index]
		self.used_refs_index += 1
		return result
#end class

def cells2dict(cells, to_json=False):
	result = list()
	for cell in cells:
		buff = cell2dict(cell, to_json=to_json)
		result.append(buff)
	return result
#end define

def cell2dict(cell, to_json=False):
	data = cell.data
	if to_json is True:
		data = data.hex()
	result = dict()
	result["@name"] = "Cell"
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
