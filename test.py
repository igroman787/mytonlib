#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from mytonlib.adnl import AdnlUdpClient

try:
	print("Connecting to c++ node")
	adnl = AdnlUdpClient()
	host = "172.104.59.125"
	port = 14432
	pubkey = "/YDNd+IwRUgL0mq21oC0L3RxrS8gTu0nciSPUrhqR78="
	result = adnl.ping(host, port, pubkey)
	print(result)
except Exception as ex:
	print(ex)
print()

try:
	print("Connecting to tonutils-storage node")
	adnl = AdnlUdpClient()
	host = "185.236.232.31"
	port = 31549
	pubkey = "3w3RC4rsAb7sLSbRdN7RpCMKUO/ayUsGTGGjlvi8Gns="
	result = adnl.ping(host, port, pubkey)
	print(result)
except Exception as ex:
	print(ex)
print()
