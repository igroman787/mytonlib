#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import math
import json
import fastcrc
from io import BytesIO as ByteStream
from bitstring import BitArray, BitStream # pip3 install bitstring
from .mytypes import Cell, Slice, Dict, int_be

def deserialize_boc(input_data):
	#print(f"deserialize_boc input_data: {input_data.hex()}")
	byte_stream = ByteStream(input_data)
	magic = bytes.fromhex("b5ee9c72")
	if byte_stream.read(4) != magic:
		raise Exception("deserialize_boc error: invalid boc magic header")
	flags_byte = byte_stream.read(1)
	data_size = int_be(byte_stream.read(1))
	flags, ref_sz_bytes = parse_flags(flags_byte)
	
	cells_num = int_be(byte_stream.read(ref_sz_bytes))
	roots_num = int_be(byte_stream.read(ref_sz_bytes))
	absent_bytes = byte_stream.read(ref_sz_bytes)
	data_len_bytes = byte_stream.read(data_size)
	data_len = int_be(data_len_bytes)
	
	root_list = byte_stream.read(roots_num * ref_sz_bytes)
	root_index = int_be(root_list[0:ref_sz_bytes])
	
	index = list()
	if flags.has_index:
		idx_data = byte_stream.read(cells_num * data_size)
		n = 0
		for i in range(cells_num):
			off = i * data_size
			val = int_be(idx_data[off : off+data_size])
			if flags.has_cache_bits:
				# TODO: check caches
				if val%2 == 1:
					n += 1
				val /= 2
			index.append(val)
		#end for
	#end if
	
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
			raise Exception("deserialize_boc error: too many refs in cell")
		#end if
		
		ln = data[offset+1]
		one_more = ln % 2
		sz = int(ln/2 + one_more)
		
		offset += 2
		if len(data)-offset < sz:
			raise Exception("deserialize_boc error: failed to parse cell payload, corrupted data")
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
			raise Exception("deserialize_boc error: failed to parse cell refs, corrupted data")
		#end if
		
		refs_index = dict()
		for y in range(refs_num):
			ref_index = data[offset:offset+ref_sz_bytes]
			refs_index[y] = int_be(ref_index)
			offset += ref_sz_bytes
		#end for
		
		refs = dict()
		for y, id in refs_index.items():
			if i == id:
				raise Exception("deserialize_boc error: recursive reference of cells")
			if id < i and index == None:
				raise Exception("deserialize_boc error: reference to index which is behind parent cell")
			if id >= cells_num:
				raise Exception("deserialize_boc error: invalid index, out of scope")
			refs[y] = cells[id]
			referred[id] = True
		#end for
		
		refs_new = list()
		for key, value in refs.items():
			refs_new.append(value)
		refs = refs_new
		
		# if not full byte
		bits_len = ln * 4
		if ln%2 != 0:
			for y in range(8):
				if (payload[len(payload)-1]>>y)&1 == 1:
					bits_len += 3 - y
					break
		#end if
		
		cells[i].special = special
		cells[i].bits_len = bits_len
		cells[i].level = level_mask
		cells[i].data = payload
		cells[i].refs = refs
		cells[i].to_dict()
	#end for
	
	roots = list()
	for y, is_ref in referred.items():
		if is_ref is False:
			roots.append(cells[y])
	#end for
	
	#if roots_num != len(roots):
	#	raise Exception(f"deserialize_boc error: roots num ({roots_num}) not match actual num ({len(roots)})")
	#end if
    
	if len(roots) == 0:
		result = None
	elif len(roots) == 1:
		result = roots[0]
	else:
		result = roots
	return result
#end define

def parse_flags(byte):
	a = byte[0] # convert byte to int
	flags = Dict()
	flags["has_index"] = a & (1<<7) > 0
	flags["has_crc32c"] = a & (1<<6) > 0
	flags["has_cache_bits"] = a & (1<<5) > 0
	flags.to_class()
	ref_sz_bytes  = a & 0b00000111
	return flags, ref_sz_bytes
#end define

def serialize_boc(cell, with_crc=False):
	"""
	serialized_boc#b5ee9c72 has_idx:(## 1) has_crc32c:(## 1) 
	  has_cache_bits:(## 1) flags:(## 2) { flags = 0 }
	  size:(## 3) { size <= 4 }
	  off_bytes:(## 8) { off_bytes <= 8 } 
	  cells:(##(size * 8)) 
	  roots:(##(size * 8)) { roots >= 1 }
	  absent:(##(size * 8)) { roots + absent <= cells }
	  tot_cells_size:(##(off_bytes * 8))
	  root_list:(roots * ##(size * 8))
	  index:has_idx?(cells * ##(off_bytes * 8))
	  cell_data:(tot_cells_size * [ uint8 ])
	  crc32c:has_crc32c?uint32
	  = BagOfCells;
	"""
	# recursively go through cells, build hash index and store unique in slice
	magic = bytes.fromhex("b5ee9c72")
	order_cells = smooth(cell)
	index(order_cells)
	cells_num = len(order_cells)
	
	# bytes needed to store num of cells
	cell_size_bits = math.log2(cells_num + 1)
	cell_size = math.ceil(cell_size_bits / 8)
	cell_size_bytes = int.to_bytes(cell_size, length=1, byteorder="little", signed=False)
	
	payload = bytes()
	for item in order_cells:
		payload += serialize_cell(item, cell_size)
	#end for
	
	# bytes needed to store len of payload
	size_bits = math.log2(len(payload) + 1)
	size = math.ceil(size_bits / 8)
	size_bytes = int.to_bytes(size, length=1, byteorder="little", signed=False)
	
	flags = 0b00000000
	if with_crc:
		flags |= 0b01000000
	flags |= cell_size
	flags_bytes = int.to_bytes(flags, length=1, byteorder="little", signed=False)
	
	result = bytes()
	result += magic
	result += flags_bytes
	result += size_bytes
	
	# cells num
	cells_num_bytes = dynamic_int_bytes(cells_num, cell_size)
	result += cells_num_bytes

	# roots num (only 1 supported for now)
	roots_num_bytes = dynamic_int_bytes(1, cell_size)
	result += roots_num_bytes

	# absent (only 0 supported for now)
	absent_bytes = dynamic_int_bytes(0, cell_size)
	result += absent_bytes

	# len of data
	tot_cells_size = len(payload)
	tot_cells_size_bytes = dynamic_int_bytes(tot_cells_size, size)
	result += tot_cells_size_bytes

	# root should have index 0
	result += dynamic_int_bytes(0, cell_size)
	result += payload
	
	if with_crc:
		buff = fastcrc.crc32.iso_hdlc(text.encode("utf8"))
		checksum = int.to_bytes(buff, length=4, byteorder="little")
		result += checksum
	#end if
	
	return result
#end define

def smooth(cell, result=None):
	if result is None:
		result = list()
	if cell in result:
		result.remove(cell)
	result.append(cell)
	for ref in cell.refs:
		smooth(ref, result)
	return result
#end define

def index(order_cells):
	for i in range(len(order_cells)):
		item = order_cells[i]
		item.index = i
#end define

def serialize_cell(cell, cell_size_bytes, is_hash=False):
	payload = cell.data
	
	unused_bits = 8 - (cell.bits_len % 8)
	if unused_bits != 8:
		payload[len(payload)-1] += 1 << (unused_bits - 1)
	#end if
	
	result = descriptors(cell) + payload
	
	if is_hash:
		#for ref in cell.refs:
		#	data = append(data, make([]byte, 2)...)
		#	binary.BigEndian.PutUint16(data[len(data)-2:], uint16(ref.maxDepth(0)))
		#}
		#for ref in cell.refs:
		#	data = append(data, ref.Hash()...)
		#}
		pass
	else:
		for ref in cell.refs:
			result += dynamic_int_bytes(ref.index, cell_size_bytes)
	#end if
	
	return result
#end define

def descriptors(cell):
	ceil_bytes_num = int(cell.bits_len / 8)
	if cell.bits_len % 8 != 0:
		ceil_bytes_num += 1
	#end if
	
	spec_bit = 0
	if cell.special:
		spec_bit = 8
	#end if
	
	d1 = len(cell.refs) + spec_bit + cell.level*32
	d2 = int(ceil_bytes_num + cell.bits_len/8)
	d1_bytes = int.to_bytes(d1, length=1, byteorder="big", signed=False)
	d2_bytes = int.to_bytes(d2, length=1, byteorder="big", signed=False)
	result = d1_bytes + d2_bytes
	return result
#end define

def dynamic_int_bytes(value, size):
	data = int.to_bytes(value, length=8, byteorder="big", signed=False)
	data_length = 8 - size
	result = data[data_length:]
	return result
#end define
