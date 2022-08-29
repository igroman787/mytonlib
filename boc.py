#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import json
from bitstring import BitArray, BitStream # pip3 install bitstring

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

def DeserializeBoc(data):
	print(f"DeserializeBoc data: {data.hex()}")
	slicer = BytesSlicer(data)
	magic = bytes.fromhex("b5ee9c72")
	if slicer(4) != magic:
		raise Exception("DeserializeBoc error: invalid boc magic header")
	flags_byte = slicer(1)
	data_size = dynInt(slicer(1))
	flags, ref_sz_bytes = ParseFlags(flags_byte)
	
	cells_num = dynInt(slicer(ref_sz_bytes))
	roots_num = dynInt(slicer(ref_sz_bytes))
	absent_bytes = slicer(ref_sz_bytes)
	data_len_bytes = slicer(data_size)
	data_len = dynInt(data_len_bytes)
	
	root_list = slicer(roots_num * ref_sz_bytes)
	root_index = dynInt(root_list[0:ref_sz_bytes])
	
	data = slicer(data_len)
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
	return roots
#end define

def ParseFlags(byte):
	a = byte[0] # convert byte to int
	flags = dict()
	flags["has_index"] = a & (1<<7) > 0
	flags["has_crc32c"] = a & (1<<6) > 0
	flags["has_cache_bits"] = a & (1<<5) > 0
	ref_sz_bytes  = a & 0b00000111
	return flags, ref_sz_bytes
#end define

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

def dynInt(data):
	return int.from_bytes(data, byteorder="big", signed=True)
#end define

def Cells2Dict(cells, to_json=False):
	result = dict()
	for i in range(len(cells)):
		cell = cells[i]
		data = cell.data
		if to_json is True:
			data = data.hex()
		result[i] = dict()
		result[i]["special"] = cell.special
		result[i]["bits_sz"] = cell.bits_sz
		result[i]["level"] = cell.level
		result[i]["data"] = data
		result[i]["refs"] = Cells2Dict(cell.refs, to_json=to_json)
	return result
#end define



state = bytes.fromhex("b5ee9c720101030100da000275c0083dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8206814ec3182dd08000006f6c8bc38e09f6a6ee44fa5bc0d340010200deff0020dd2082014c97ba218201339cbab19f71b0ed44d0d31fd31f31d70bffe304e0a4f2608308d71820d31fd31fd31ff82313bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a204f901541055f910f2a3f8009320d74a96d307d402fb00e8d101a4c8cb1fcb1fcbffc9ed5400500000005f29a9a31772c9ed6b62a6e2eba14a93b90462e7a367777beb8a38fb15b9f33844d22ce2ff")
state = bytes.fromhex("b5ee9c720102350100051e000277c0021137b0bc47669b3267f1de70cbb0cef5c728b8d8c7890451e8613b2d899827026a886043179d3f6000006e233be8722201d7d239dba7d818134001020114ff00f4a413f4bcf2c80b0d021d0000000105036248628d00000000e003040201cb05060013a03128bb16000000002002012007080043d218d748bc4d4f4ff93481fd41c39945d5587b8e2aa2d8a35eaf99eee92d9ba96004020120090a0201200b0c00432c915453c736b7692b5b4c76f3a90e6aeec7a02de9876c8a5eee589c104723a18020004307776cd691fbe13e891ed6dbd15461c098b1b95c822af605be8dc331e7d45571002000433817dc8de305734b0c8a3ad05264e9765a04a39dbe03dd9973aa612a61f766d7c02000431f8c67147ceba1700d3503e54c0820f965f4f82e5210e9a3224a776c8f3fad1840200201200e0f020148101104daf220c7008e8330db3ce08308d71820f90101d307db3c22c00013a1537178f40e6fa1f29fdb3c541abaf910f2a006f40420f90101d31f5118baf2aad33f705301f00a01c20801830abcb1f26853158040f40e6fa120980ea420c20af2670edff823aa1f5340b9f2615423a3534e2a2d2b2c0202cc12130201201819020120141502016616170003d1840223f2980bc7a0737d0986d9e52ed9e013c7a21c2b2f002d00a908b5d244a824c8b5d2a5c0b5007404fc02ba1b04a0004f085ba44c78081ba44c3800740835d2b0c026b500bc02f21633c5b332781c75c8f20073c5bd0032600201201a1b02012020210115bbed96d5034705520db3c8340201481c1d0201201e1f0173b11d7420c235c6083e404074c1e08075313b50f614c81e3d039be87ca7f5c2ffd78c7e443ca82b807d01085ba4d6dc4cb83e405636cf0069006031003daeda80e800e800fa02017a0211fc8080fc80dd794ff805e47a0000e78b64c00015ae19574100d56676a1ec40020120222302014824250151b7255b678626466a4610081e81cdf431c24d845a4000331a61e62e005ae0261c0b6fee1c0b77746e102d0185b5599b6786abe06fedb1c68a2270081e8f8df4a411c4605a400031c34410021ae424bae064f613990039e2ca840090081e886052261c52261c52265c4036625ccd88302d02012026270203993828290111ac1a6d9e2f81b609402d0015adf94100cc9576a1ec1840010da936cf0557c1602d0015addc2ce0806ab33b50f6200220db3c02f265f8005043714313db3ced542d34000ad3ffd3073004a0db3c2fae5320b0f26212b102a425b3531cb9b0258100e1aa23a028bcb0f269820186a0f8010597021110023e3e308e8d11101fdb3c40d778f44310bd05e254165b5473e7561053dcdb3c54710a547abc2e2f32300020ed44d0d31fd307d307d33ff404f404d10048018e1a30d20001f2a3d307d3075003d70120f90105f90115baf2a45003e06c2170542013000c01c8cbffcb0704d6db3ced54f80f70256e5389beb198106e102d50c75f078f1b30542403504ddb3c5055a046501049103a4b0953b9db3c5054167fe2f800078325a18e2c268040f4966fa52094305303b9de208e1638393908d2000197d3073016f007059130e27f080705926c31e2b3e63006343132330060708e2903d08308d718d307f40430531678f40e6fa1f2a5d70bff544544f910f2a6ae5220b15203bd14a1236ee66c2232007e5230be8e205f03f8009322d74a9802d307d402fb0002e83270c8ca0040148040f44302f0078e1771c8cb0014cb0712cb0758cf0158cf1640138040f44301e201208e8a104510344300db3ced54925f06e234001cc8cb1fcb07cb07cb3ff400f400c9")

cells = DeserializeBoc(state)
cells_dict = Cells2Dict(cells, to_json=True)
print(f"cells: {cells}")
print("cells:", json.dumps(cells_dict, indent=4))

















