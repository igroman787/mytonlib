#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import binascii


class Schemes:
	def __init__(self, filepath):
		self.schemes_names = dict()
		self.schemes_ids = dict()
		self.Parse(filepath)
	#end define
	
	def Parse(self, filepath):
		file = open(filepath, "rt")
		text = file.read()
		file.close()
		lines = text.split('\n')
		for line in lines:
			scheme = Scheme(self, line)
			self.schemes_names[scheme.name] = scheme
			self.schemes_ids[scheme.id] = scheme.name
		#end for
	#end define
	
	def GetSchemeByName(self, scheme_name):
		return self.schemes_names.get(scheme_name)
	#end define
	
	def GetSchemeById(self, id):
		scheme_name = self.schemes_ids.get(id)
		return self.schemes_names.get(scheme_name)
	#end define
#end class

class Scheme:
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
		self.id = self.CRC32(text)
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
	
	def CRC32(self, text):
		buff = binascii.crc32(text.encode("utf8"))
		result = int.to_bytes(buff, length=4, byteorder="little")
		return result
	#end define
	
	def Int(self, data):
		return int.from_bytes(data, byteorder="little", signed=True)
	#end define
	
	def Deserialize(self, data):
		if type(data) == BytesSlicer:
			slicer = data
		elif type(data) == bytes:
			slicer = BytesSlicer(data)
		else:
			raise Exception("Deserialize error. Input parameter type must be BytesSlicer")
		#end if
		
		result = Dict()
		for var_name, var_type in self.vars.items():
			if var_type == "int":
				buff = slicer(4)
				var_value = self.Int(buff)
			elif var_type == "long":
				buff = slicer(8)
				var_value = self.Int(buff)
			elif var_type == "int256":
				buff = slicer(32)
				var_value = buff.hex()
			elif var_type == "bytes":
				var_value = slicer.bytes
			else:
				scheme = self.schemes.GetSchemeByName(var_type)
				var_value = scheme.Deserialize(slicer)
			result[var_name] = var_value
		result.toClass()
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
