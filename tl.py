#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import binascii


class TlSchemes:
	def __init__(self):
		self.schemes_names = dict()
		self.schemes_ids = dict()
	#end define
	
	def LoadSchemes(self, filepath):
		if os.path.isfile(filepath):
			self.LoadSchemesFromFile(filepath)
		elif os.path.isdir(filepath):
			self.LoadSchemesFromDir(filepath)
	#end define
	
	def LoadSchemesFromFile(self, filepath):
		file = open(filepath, "rt")
		text = file.read()
		file.close()
		lines = text.split('\n')
		for line in lines:
			scheme = TlScheme(self, line)
			if scheme.name == None:
				continue
			self.schemes_names[scheme.name] = scheme
			self.schemes_ids[scheme.id] = scheme.name
		#end for
	#end define
	
	def LoadSchemesFromDir(self, dir):
		for file in os.listdir(dir):
			if file.endswith(".tl"):
				filepath = dir + file
				self.LoadSchemesFromFile(filepath)
	#end define
	
	def GetSchemeByName(self, scheme_name):
		result = self.schemes_names.get(scheme_name)
		if result is None:
			raise Exception(f"GetSchemeByName error: scheme '{scheme_name}' not found")
		return result
	#end define
	
	def GetSchemeById(self, id):
		scheme_name = self.schemes_ids.get(id)
		result = self.schemes_names.get(scheme_name)
		if result is None:
			raise Exception(f"GetSchemeById error: scheme '{id.hex()}' not found")
		return result
	#end define
#end class

class TlScheme:
	def __init__(self, schemes, text):
		self.schemes = schemes
		self.id = None
		self.name = None
		self.class_name = None
		self.vars = None
		self.Parse(text)
	#end define
	
	def Parse(self, text):
		end = ';'
		if end in text:
			text = text.replace(end, '')
		#end if
		
		sep = '='
		if sep not in text:
			return
		buff = text.split(' ')
		self.id = CRC32(text)
		self.name = buff.pop(0)
		self.class_name = buff.pop(-1)
		buff.remove(sep)
		vars = dict()
		for item in buff.copy():
			sep = ':'
			if sep not in item:
				continue
			buff = item.split(sep)
			var_name = buff.pop(0)
			var_type = buff.pop()
			vars[var_name] = var_type
		self.vars = vars
	#end define
	
	def LoadBytes(self, slicer, alen=4):
		buff = slicer(1)
		if buff == bytes.fromhex("fe"):
			buff = slicer(3)
		dlen = int.from_bytes(buff, byteorder="little")
		rdata = slicer(dlen)
		
		if dlen % alen != 0:
			nlen = alen - dlen % alen
			null = slicer(nlen)
		return rdata
	#end define
	
	def Deserialize(self, data):
		if type(data) == BytesSlicer:
			slicer = data
		elif type(data) == bytes:
			slicer = BytesSlicer(data)
		else:
			raise Exception("Deserialize error: Input parameter type must be BytesSlicer")
		#end if
		
		result = Dict()
		for var_name, var_type in self.vars.items():
			if var_type == "int":
				buff = slicer(4)
				var_value = Int(buff)
			elif var_type == "long":
				buff = slicer(8)
				var_value = Int(buff)
			elif var_type == "int256":
				buff = slicer(32)
				var_value = buff.hex()
			elif var_type == "bytes":
				var_value = self.LoadBytes(slicer)
			else:
				scheme = self.schemes.GetSchemeByName(var_type)
				var_value = scheme.Deserialize(slicer)
			result[var_name] = var_value
		result.toClass()
		return result
	#end define
	
	def Serialize(self, **data):
		result = bytes()
		for var_name, var_type in self.vars.items():
			var_value = data.get(var_name)
			if var_value == None:
				raise Exception(f"Serialize error: '{var_name}' not found in input parameters.")
			if var_type == "int":
				result += Int2Bytes(var_value)
			elif var_type == "long":
				result += Long2Bytes(var_value)
			elif var_type == "int256":
				result += bytes.fromhex(var_value)
			else:
				scheme = self.schemes.GetSchemeByName(var_type)
				result += scheme.Serialize(**var_value)
		return result
	#end define
#end class

class BytesSlicer:
	def __init__(self, data):
		self.bytes = data
	#end define

	def __call__(self, dlen):
		data = self.bytes[:dlen]
		self.bytes = self.bytes[dlen:]
		return data
	#end define
#end class

class Dict(dict):
	def toClass(self):
		for key, value in self.items():
			setattr(self, key, value)
		#end for
	#end define
#end class

def TlLen(data):
	dlen = len(data)
	if dlen < 254:
		dlen = dlen.to_bytes(1, byteorder="little")
	else:
		buff = bytes.fromhex("fe")
		dlen = buff + dlen.to_bytes(3, byteorder="little")
	return dlen
#end define

def CRC32(text):
	buff = binascii.crc32(text.encode("utf8"))
	result = int.to_bytes(buff, length=4, byteorder="little")
	return result
#end define

def Int(data):
	return int.from_bytes(data, byteorder="little", signed=True)
#end define

def Int2Bytes(data):
	return int.to_bytes(data, length=4, byteorder="little", signed=True)
#end define

def Long2Bytes(data):
	return int.to_bytes(data, length=8, byteorder="little", signed=True)
#end define

