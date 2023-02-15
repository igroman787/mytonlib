#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import base64
import fastcrc



def hex2dec(h):
	return int(h, base=16)
#end define

def dec2hex_addr(dec):
	h = dec2hex(dec)
	h64 = h.rjust(64, '0')
	return h64
#end define

def dec2hex(dec):
	h = f"{dec:x}"
	if len(h) % 2 > 0:
		h = '0' + h
	return h
#end define

def parse_addr(inputAddr):
	if IsAddrB64(inputAddr):
		workchain, addr, bounceable = ParseAddrB64(inputAddr)
		return workchain, addr
	elif IsAddrFull(inputAddr):
		workchain, addr = ParseAddrFull(inputAddr)
		return workchain, addr
	else:
		raise Exception(f"parse_addr error: input address is not a adress: {inputAddr}")
#end define

def ParseAddrFull(addrFull):
	buff = addrFull.split(':')
	workchain = int(buff[0])
	addr = buff[1]
	addrBytes = bytes.fromhex(addr)
	if len(addrBytes) != 32:
		raise Exception("ParseAddrFull error: addrBytes is not 32 bytes")
	return workchain, addr
#end define

def ParseAddrB64(addrB64):
	buff = addrB64.replace('-', '+')
	buff = buff.replace('_', '/')
	buff = buff.encode()
	b = base64.b64decode(buff)
	testnet_int = (b[0] & 0x80)
	if testnet_int == 0:
		testnet = False
	else:
		testnet = True
	bounceable_int = (b[0] & 0x40)
	if bounceable_int != 0:
		bounceable = False
	else:
		bounceable = True
	#end if

	# get wc and addr
	workchain_bytes = b[1:2]
	addr_bytes = b[2:34]
	crc_bytes = b[34:36]
	crc_data = bytes(b[:34])
	crc = int.from_bytes(crc_bytes, "big")
	check_crc = fastcrc.crc16.xmodem(crc_data)
	if crc != check_crc:
		raise Exception("ParseAddrB64 error: crc do not match")
	#end if

	workchain = int.from_bytes(workchain_bytes, "big", signed=True)
	addr = addr_bytes.hex()
	
	return workchain, addr, bounceable
#end define

def IsAddr(addr):
	isAddrB64 = IsAddrB64(addr)
	isAddrFull = IsAddrFull(addr)
	if isAddrB64 or isAddrFull:
		return True
	return False
#end define

def IsAddrB64(addr):
	try:
		ParseAddrB64(addr)
		return True
	except: pass
	return False
#end define

def IsAddrFull(addr):
	try:
		ParseAddrFull(addr)
		return True
	except: pass
	return False
#end define
