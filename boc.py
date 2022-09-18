#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import json
from io import BytesIO as ByteStream
from bitstring import BitArray, BitStream # pip3 install bitstring
from mytypes import Cell, Slice

def deserialize_boc(data):
	#print(f"deserialize_boc data: {data.hex()}")
	byte_stream = ByteStream(data)
	magic = bytes.fromhex("b5ee9c72")
	if byte_stream.read(4) != magic:
		raise Exception("deserialize_boc error: invalid boc magic header")
	flags_byte = byte_stream.read(1)
	data_size = dynInt(byte_stream.read(1))
	flags, ref_sz_bytes = parse_flags(flags_byte)
	
	cells_num = dynInt(byte_stream.read(ref_sz_bytes))
	roots_num = dynInt(byte_stream.read(ref_sz_bytes))
	absent_bytes = byte_stream.read(ref_sz_bytes)
	data_len_bytes = byte_stream.read(data_size)
	data_len = dynInt(data_len_bytes)
	
	root_list = byte_stream.read(roots_num * ref_sz_bytes)
	root_index = dynInt(root_list[0:ref_sz_bytes])
	
	data = byte_stream.read(data_len)
	index = None
	offset = 0
	cells = dict()
	referred = dict()
	for i in range(cells_num):
		cells[i] = Cell()
		referred[i] = False
	#end for
	
	for i in range(cells_num):
		if index != None:
			offset = 0
			if i > 0:
				offset = index[i-1]
		#end if
		
		flags = data[offset]
		refs_num = (flags & 0b111)
		special = (flags & 0b1000) != 0
		with_hashes = (flags & 0b10000) != 0
		level_mask = flags >> 5
		
		if refs_num > 4:
			raise Exception("DeserializeCells error: too many refs in cell")
		#end if
		
		ln = data[offset+1]
		one_more = ln % 2
		sz = int(ln/2 + one_more)
		
		offset += 2
		if len(data)-offset < sz:
			raise Exception("DeserializeCells error: failed to parse cell payload, corrupted data")
		#end if
		
		if with_hashes is True:
			mask_bits = int(math.ceil(math.log2(level_mask + 1)))
			hashes_num = mask_bits + 1
			
			hash_size = 32
			depth_size = 2
			offset += hashes_num*hash_size + hashes_num*depth_size
			# TODO: check depth and hashes
		#end if
		
		payload = data[offset:offset+sz]
		offset += sz
		
		
		if len(data)-offset < refs_num*ref_sz_bytes :
			raise Exception("DeserializeCells error: failed to parse cell refs, corrupted data")
		#end if
		
		refs_index = dict()
		for y in range(refs_num):
			ref_index = data[offset:offset+ref_sz_bytes]
			refs_index[y] = dynInt(ref_index)
			offset += ref_sz_bytes
		#end for
		
		refs = dict()
		for y, id in refs_index.items():
			if i == id:
				raise Exception("DeserializeCells error: recursive reference of cells")
			if id < i and index == None:
				raise Exception("DeserializeCells error: reference to index which is behind parent cell")
			if id >= cells_num:
				raise Exception("DeserializeCells error: invalid index, out of scope")
			refs[y] = cells[id]
			referred[id] = True
		#end for
		
		# if not full byte
		bits_sz = ln * 4
		if ln%2 != 0:
			for y in range(8):
				if (payload[len(payload)-1]>>y)&1 == 1:
					bits_sz += 3 - y
					break
		#end if
		
		cells[i].special = special
		cells[i].bits_sz = bits_sz
		cells[i].level = level_mask
		cells[i].data = payload
		cells[i].refs = refs
	#end for
	
	roots = list()
	for y, is_ref in referred.items():
		if is_ref is False:
			roots.append(cells[y])
	#end for
	
	if len(roots) != roots_num:
		raise Exception("DeserializeCells error: roots num not match actual num")
	#end if
    
	if len(roots) == 1:
		result = roots[0]
	else:
		result = roots
	return result
#end define

def parse_flags(byte):
	a = byte[0] # convert byte to int
	flags = dict()
	flags["has_index"] = a & (1<<7) > 0
	flags["has_crc32c"] = a & (1<<6) > 0
	flags["has_cache_bits"] = a & (1<<5) > 0
	ref_sz_bytes  = a & 0b00000111
	return flags, ref_sz_bytes
#end define

def dynInt(data):
	return int.from_bytes(data, byteorder="big", signed=True)
#end define
