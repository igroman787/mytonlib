#!/usr/bin/env python3
# -*- coding: utf_8 -*-

#import os # debug
import time
import json
#import psutil # debug
import socket
import random
import threading
import urllib.request
from .adnl import AdnlTcpClient
from .mytypes import Dict, Thread
from .utils import int2ip, bcolors
#import objgraph # debug


class AdnlTcpClientWithBalancer:
	def __init__(self, global_config_path):	
		self.global_config = None
		self.liteservers = list()
		self.max_liteservers = 300
		self.replication_requests_number = 0
		self._read_global_config(global_config_path)
		
		# Start clear liteservers thread
		self._start_thread(self._clear_liteservers_thr)
		self._start_thread(self._replicate_liteserver_thr)
	#end define
	
	def _start_thread(self, func, *args, **kwargs):
		tnum = random.randint(1, 999999)
		tname = f"{func.__name__}_{tnum}"
		thr = Thread(target=func, args=args, name=tname, daemon=True)
		thr.start()
		return thr
	#end define
	
	def _read_global_config(self, global_config_path):
		if global_config_path.startswith("https://"):
			self._read_global_config_from_url(global_config_path)
		else:
			self._read_global_config_from_file(global_config_path)
	#end define
	
	def _read_global_config_from_url(self, url):
		file_path = "/tmp/global_config_for_mytonlib.json"
		with urllib.request.urlopen(url) as response, open(file_path, 'wb') as file:
			data = response.read()
			file.write(data)
		self._read_global_config_from_file(file_path)
	#end define
	
	def _read_global_config_from_file(self, global_config_path):
		with open(global_config_path, 'rt') as file:
			text = file.read()
			self.global_config = Dict(json.loads(text))
		self._read_liteservers()
	#end define
	
	def _read_liteservers(self):
		config_liteservers = self.global_config.liteservers.copy()
		for index in range(len(config_liteservers)):
			config_liteserver = config_liteservers[index]
			self._try_add_liteserver(index, config_liteserver)
	#end define
	
	def _try_add_liteserver(self, index, config_liteserver):
		try:
			self._add_liteserver(index, config_liteserver)
		except ConnectionError:
			self.global_config.liteservers.remove(config_liteserver)
		except socket.timeout:
			self.global_config.liteservers.remove(config_liteserver)
	#end define
	
	def _add_liteserver(self, index, config_liteserver):
		adnl = AdnlTcpClient()
		host = int2ip(config_liteserver.ip)
		adnl.connect(host, config_liteserver.port, config_liteserver.id.key)
		liteserver = Dict()
		liteserver.index = index
		liteserver.free = True
		liteserver.adnl = adnl
		liteserver.low_level = 0
		liteserver.cmd = None
		liteserver.last_use = int(time.time())
		self.liteservers.append(liteserver)
	#end define
	
	def _clear_liteservers_thr(self):
		while True:
			time.sleep(5)
			self._clear_liteservers()
			#self._debug_thrs()
			#self._debug_lite_servers()
	#end define
	
	def _replicate_liteserver_thr(self):
		while True:
			time.sleep(0.1)
			if self.replication_requests_number > 0:
				self._replicate_liteserver()
				self.replication_requests_number -= 1
			#end if
	#end define
	
	def _debug_lite_servers(self):
		with open(f"_debug_lite_servers.txt", 'wt') as file:
			format = "%d.%m.%Y %H:%M:%S"
			datetime = time.localtime(time.time())
			ntime = time.strftime(format, datetime)
			buff = [f"time: {ntime}, liteservers: {len(self.liteservers)}, threads: {threading.active_count()}"]
			for liteserver in self.liteservers:
				idle_time = int(time.time()) - liteserver.last_use
				buff.append(f"<ping={liteserver.adnl.ping_result}, low_level={liteserver.low_level}, free={liteserver.free}, idle_time={idle_time} cmd={liteserver.cmd}>")
			result = "\n".join(buff) + '\n'
			file.write(result)
	#end define
	
	def _debug_thrs(self):
		thrs_buff = dict()
		used_thrs = list()
		unused_thrs = list()
		thrs_parents = dict()
		for thr in threading.enumerate():
			if type(thr) == threading._MainThread:
				thrs_parents[thr.name] = None
			else:
				thrs_parents[thr.name] = thr.parent.name
			thrs_buff[thr.name] = thr
			unused_thrs.append(thr)
		#end for
		
		thrs_tree = dict()
		main_thr = threading.main_thread()
		thrs_tree[main_thr.name] = self._debug_thrs_qwe(main_thr.name, thrs_parents.items(), used_thrs, unused_thrs, thrs_buff)
		
		time_now = time.time()
		format = "%d.%m.%Y %H:%M:%S"
		datetime = time.localtime(time_now)
		ntime = time.strftime(format, datetime)
		process = psutil.Process(os.getpid())
		memory_using = process.memory_info().rss / 10**6
		print_tree = [f"time: {ntime}, liteservers: {len(self.liteservers)}, threads: {len(used_thrs)} + {len(unused_thrs)}, memory: {memory_using}"]
		self._debug_thrs_rty(print_tree, '', thrs_tree, thrs_buff)
		for thr in unused_thrs:
			work_time = int(time_now - thr.start_time)
			work_str = f" work {work_time} seconds"
			print_tree += [f"<{thr.name}{work_str}>"]
		#end for
		
		with open(f"_debug_thrs.txt", 'wt') as file:
			text = "\n".join(print_tree) + '\n'
			file.write(text)
	#end define
	
	def _debug_thrs_rty(self, print_tree, prefix, thrs_tree, thrs_buff):
		i = 1
		time_now = time.time()
		for thr_name, thrs in thrs_tree.items():
			thr = thrs_buff.get(thr_name)
			if i == len(thrs_tree):
				symbol = '└─'
				suffix = '  '
			else:
				symbol = '├─'
				suffix = ' │'
			if thr_name.startswith('_'):
				thr_name = thr_name[1:]
			#end if
			
			if not hasattr(thr, "start_time"):
				work_str = ""
			else:
				work_time = int(time_now - thr.start_time)
				work_str = f" work {work_time} seconds"
			#end if
			
			print_tree += [f"{prefix} {symbol} <{thr_name}{work_str}>"]
			self._debug_thrs_rty(print_tree, prefix + suffix, thrs, thrs_buff)
			i += 1
	#end define
	
	def _debug_thrs_qwe(self, main_thr_name, thrs_parents_items, used_thrs, unused_thrs, thrs_buff):
		used_thrs.append(main_thr_name)
		thr = thrs_buff.get(main_thr_name)
		if thr in unused_thrs:
			unused_thrs.remove(thr)
		thrs_tree = dict()
		thrs_name = [thr_name for thr_name, parent_name in thrs_parents_items if parent_name == main_thr_name]
		for thr_name in thrs_name:
			thrs_tree[thr_name] = self._debug_thrs_qwe(thr_name, thrs_parents_items, used_thrs, unused_thrs, thrs_buff)
		return thrs_tree
	#end define
	
	def _clear_liteservers(self):
		for liteserver in self.liteservers.copy():
			idle_time = int(time.time()) - liteserver.last_use
			if liteserver.adnl.ping_result is None or idle_time > 100:
				#print(f"liteservers.remove: {liteserver}, adnl:{liteserver.adnl}")
				self.liteservers.remove(liteserver)
				#objgraph.show_backrefs([liteserver], filename='_debug_objgraph_liteserver.png')
				#objgraph.show_backrefs([liteserver.adnl], filename='_debug_objgraph_adnl.png')
				liteserver.adnl.__del__()
	#end define
	
	def _get_free_liteserver(self):
		free_liteservers = [liteserver for liteserver in self.liteservers if liteserver.adnl.ping_result != None and liteserver.free == True]
		free_liteservers = sorted(free_liteservers, key=lambda liteserver: liteserver.last_use, reverse=True)
		if len(free_liteservers) > 0:
			liteserver = free_liteservers.pop(0)
			self._lock_liteserver(liteserver)
			return liteserver
		else:
			#print(f"self.replication_requests_number: {self.replication_requests_number}")
			self.replication_requests_number += 1
			time.sleep(1)
			return self._get_free_liteserver()
		#end if
	#end define
	
	def _get_random_item_from_list(self, arr):
		if len(arr) > 0:
			return random.choice(arr)
		else:
			return None
	#end define
	
	def _get_free_liteservers(self):
		filtered_liteservers = [liteserver for liteserver in self.liteservers if liteserver.adnl.ping_result != None and liteserver.free == True]
		#sorted_liteservers = sorted(self.liteservers, key=lambda liteserver: liteserver.adnl.ping_result)
		return filtered_liteservers
	#end define
	
	def _sleep(self):
		while True:
			time.sleep(10)
	#end define
	
	def _replicate_liteserver(self):
		#print(f"_replicate_liteserver: {len(self.liteservers)}")
		
		if len(self.liteservers) > self.max_liteservers:
			time.sleep(1)
			self._unlock_replicator()
			print(f"{bcolors.red} liteservers > max_liteservers {bcolors.endc}")
			return
		#end if
		
		temp_liteservers = dict()
		for liteserver in self.liteservers:
			if liteserver.adnl.ping_result == None or liteserver.adnl.ping_result > 300:
				continue
			if liteserver.index not in temp_liteservers:
				temp_liteservers[liteserver.index] = 0
			temp_liteservers[liteserver.index] += 1
		#end for
		
		config_liteservers = self.global_config.liteservers
		for index in range(len(config_liteservers)):
			if index not in temp_liteservers:
				temp_liteservers[index] = 0
		#end for
		
		if len(temp_liteservers) == 0:
			print(f"self.liteservers: {self.liteservers}")
			print(f"temp_liteservers: {temp_liteservers}")
			raise Exception("_replicate_liteserver error: temp_liteservers epmty")
		#end if
		
		sorted_temp_liteservers = sorted(temp_liteservers.items(), key=lambda item: item[1])
		index = sorted_temp_liteservers[0][0]
		config_liteserver = config_liteservers[index]
		self._add_liteserver(index, config_liteserver)
	#end define
	
	def _lock_liteserver(self, liteserver):
		liteserver.last_use = int(time.time())
		liteserver.free = False
	#end define
	
	def _unlock_liteserver(self, liteserver):
		liteserver.free = True
		liteserver.cmd = None
	#end define
	
	def _try(self, func, *args, **kwargs):
		err = None
		for step in range(1, 4):
			try:
				result = func(*args, **kwargs)
				return result
			except Exception as ex:
				time.sleep(step)
				err = ex
		raise Exception(err)
	#end define
	
	def get_messages_from_transaction(self, block, trans):
		account_id = {"workchain": block.workchain, "id": trans.account}
		data = self.adnl.get_one_transaction(block, account_id, trans.lt)
		message_list = list()
		if data is None:
			return message_list
		#end if
		
		message_list.append(data.in_msg)
		if data.out_msgs != None:
			for key, message in data.out_msgs.items():
				message_list.append(message)
		message_list = [message for message in message_list if message != None]
		return message_list
	#end define
	
	def _adnl_request_new(self, func_name, *args, **kwargs):
		err = None
		liteserver = self._get_free_liteserver()
		liteserver.cmd = f"{func_name}{args}"
		try:
			func = getattr(liteserver.adnl, func_name)
			result = self._try(func, *args, **kwargs)
		except Exception as ex:
			liteserver.low_level += 1
			err = ex
		finally:
			self._unlock_liteserver(liteserver)
		if err is None:
			return result
		else:
			raise Exception(err)
	#end define
	
	def _adnl_request(self, func_name, *args, **kwargs):
		liteserver = self._get_free_liteserver()
		liteserver.cmd = f"{func_name}{args}"
		func = getattr(liteserver.adnl, func_name)
		result = func(*args, **kwargs)
		self._unlock_liteserver(liteserver)
		return result
	#end define
	
	def get_time(self):
		return self._adnl_request("get_time")
	#end define
	
	def get_masterchain_info(self):
		return self._adnl_request("get_masterchain_info")
	#end define
	
	def get_account_state(self, input_addr, block_id_ext=None):
		return self._adnl_request("get_account_state", input_addr, block_id_ext)
	#end define
	
	def run_smc_method(self, input_addr, method_name, params=None, block_id_ext=None):
		return self._adnl_request("run_smc_method", input_addr, method_name, params, block_id_ext)
	#end define
	
	def run_smc_method_local(self, input_addr, method_name, params=None, block_id_ext=None):
		return self._adnl_request("run_smc_method_local", input_addr, method_name, params, block_id_ext)
	#end define
	
	def get_all_shards_info(self, block_id_ext=None):
		return self._adnl_request("get_all_shards_info", block_id_ext)
	#end define
	
	def get_config_params(self, params, block_id_ext=None):
		return self._adnl_request("get_config_params", params, block_id_ext)
	#end define
	
	def get_block_header(self, block_id_ext=None):
		return self._adnl_request("get_block_header", block_id_ext)
	#end define
	
	def get_block(self, block_id_ext=None):
		return self._adnl_request("get_block", block_id_ext)
	#end define
	
	def get_last_transactions(self, input_addr, count=10):
		return self._adnl_request("get_last_transactions", input_addr, count)
	#end define
	
	def get_block_transactions(self, block_id_ext, count=1000):
		return self._adnl_request("get_block_transactions", block_id_ext, count)
	#end define
	
	def get_one_transaction(self, block_id_ext, account_id, trans_lt):
		return self._adnl_request("get_one_transaction", block_id_ext, account_id, trans_lt)
	#end define
	
	def lookup_block(self, workchain, shard, seqno=-1, lt=None, utime=None):
		return self._adnl_request("lookup_block", workchain, shard, seqno, lt, utime)
	#end define
	
	def send_ext_msg(self, body):
		return self._adnl_request("send_ext_msg", body)
	#end define
#end class
