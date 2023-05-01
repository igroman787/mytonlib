#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import time
import random
import logging
import threading
import datetime as DateTimeLibrary
from .utils import bcolors
from .mytypes import Dict, Thread


class TonBlocksScanner():
	def __init__(self, adnl, **kwargs):
		self.queue = dict()
		self.adnl = adnl
		self.prev_master_block = None
		self.prev_shards_block = dict()
		self.blocks_num = 0
		self.trans_num = 0
		self.messages_num = 0
		self.nbr = kwargs.get("nbr") #_new_block_reaction
		self.ntr = kwargs.get("ntr") #_new_trans_reaction
		self.nmr = kwargs.get("nmr") #_new_message_reaction
		self.sync = kwargs.get("sync", False)
		self.delay = 0
		self.working = True
		self.skip_messages = kwargs.get("skip_messages", True)
	#end define
	
	def __del__(self):
		self.working = False
	#end define
	
	def _add_log(self, input_text, mode="info"):
		if not os.path.isdir("logs"):
			os.mkdir("logs")
		if mode == "info":
			color_start = bcolors.blue + bcolors.bold
		elif mode == "warning":
			color_start = bcolors.yellow + bcolors.bold
		elif mode == "error":
			color_start = bcolors.red + bcolors.bold
		elif mode == "debug":
			color_start = bcolors.magenta + bcolors.bold
		else:
			color_start = bcolors.underline + bcolors.bold
		tname = threading.currentThread().getName()
		time_text = DateTimeLibrary.datetime.utcnow().strftime("%d.%m.%Y, %H:%M:%S.%f")[:-3]
		mode_text = f"{color_start}[{mode:>10}]{bcolors.endc}"
		if mode == "error":
			color_start = bcolors.red + bcolors.bold
		else:
			color_start = bcolors.green + bcolors.bold
		thread_text = f"{color_start}<{tname:>14}>{bcolors.endc}"
		log_text = f"{mode_text} {time_text} (UTC) {thread_text} {input_text}"
		#with open(f"logs/{tname}.log", 'a') as file:
		#	file.write(log_text + '\n')
		print(log_text)
	#end define

	def run(self):
		self._start_thread(self._scan_master_blocks)
	#end define
	
	def set_start_block(self, workchain, shard, seqno):
		block = self._try_with_exception(self.adnl.lookup_block, workchain, shard, seqno)
		shards = self._try_with_exception(self.adnl.get_all_shards_info, block)
		for shard in shards:
			self._set_shard_prev_block(shard)
		self.prev_master_block = block
	#end define

	def _start_thread(self, func, *args, **kwargs):
		tnum = random.randint(1, 999999)
		tname = f"{func.__name__}_{tnum}"
		thr = Thread(target=func, args=args, name=tname, daemon=True)
		#setattr(thr, "parent", threading.current_thread())
		#setattr(thr, "start_time", time.time())
		thr.start()
		return thr
	#end define
	
	def _try(self, func, *args, **kwargs):
		try:
			return func(*args, **kwargs)
		except Exception as err:
			self._add_log(f"scanner _try {func.__name__} error: {err}")
	#end define

	def _start_with_mode(self, func, *args, **kwargs):
		if self.sync:
			func(*args, **kwargs)
		else:
			self._start_thread(func, *args, **kwargs)
	#end define

	def _try_with_exception(self, func, *args, **kwargs):
		for step in range(3):
			try:
				result = func(*args, **kwargs)
				return result
			except Exception as ex:
				time.sleep(1)
				err = ex
				print(f"scanner _try_with_exception {func.__name__} step: {step}, error: {err}")
				self._add_log(f"scanner _try_with_exception {func.__name__} step: {step}, error: {err}")
		raise Exception(err)
	#end define
	
	def _try_with_exception_old(self, func, *args, **kwargs):
		result = func(*args, **kwargs)
		return result
	#end define

	def _scan_master_blocks(self):
		while self.working:
			self._scan_master_block()
			time.sleep(1)
	#end define

	def _scan_master_block(self):
		mc_info = self._try_with_exception(self.adnl.get_masterchain_info)
		block = mc_info.last
		#self._start_thread(self._search_miss_blocks, block, self.prev_master_block)
		self._search_miss_blocks(block, self.prev_master_block)
		if block != self.prev_master_block:
			self._start_thread(self._read_master_block, block)
			self.prev_master_block = block
	#end define

	def _read_master_block(self, block):
		#self._add_log(f"_read_master_block ({block.workchain},{block.shard},{block.seqno})")
		self._start_thread(self._new_block_reaction, block)
		shards = self._try_with_exception(self.adnl.get_all_shards_info, block)
		self._add_log(f"{bcolors.yellow} block: ({block.workchain},{block.shard},{block.seqno}) {bcolors.endc} -> {len(shards)} shards")
		shards_thrs = dict()
		for shard_block in shards:
			#print(f"{bcolors.yellow}                           ---> {shard_block.shard}")
			shards_thrs[shard_block.shard] = self._start_thread(self._read_shard_block, shard_block)
		for shard_block in shards:
			shards_thrs[shard_block.shard].join()
	#end define
	
	def _start_thread_with_queue(self, func, *args, **kwargs):
		#self._add_log("_start_thread_with_queue")
		fname = func.__name__
		if fname not in self.queue:
			self.queue[fname] = list()
		queue = self.queue.get(fname)
		while len(queue) >= 4:
			time.sleep(0.1)
		thr = self._start_thread(func, *args, **kwargs)
		queue.append(thr.name)
		#self._add_log(f"queue.append {thr.name}")
		self._start_thread(self._queue_handler, thr, fname)
		return thr
	#end define
	
	def _queue_handler(self, thr, fname):
		while thr.is_alive():
			time.sleep(0.1)
		queue = self.queue.get(fname)
		queue.remove(thr.name)
		#self._add_log(f"queue.remove {thr.name}")
	#end define

	def _read_shard_block(self, block):
		#self._add_log(f"_read_shard_block ({block.workchain},{block.shard},{block.seqno})")
		prev_block = self._get_shard_prev_block(block.shard)
		self._set_shard_prev_block(block)
		#self._start_thread(self._search_miss_blocks, block, prev_block)
		self._search_miss_blocks(block, prev_block)
		if block != prev_block:
			self._start_thread(self._new_block_reaction, block)
	#end define

	def _search_miss_blocks(self, block, prev_block):
		#self._add_log(f"_search_miss_blocks ({block.workchain},{block.shard},{block.seqno} - {prev_block.seqno})")
		if prev_block is None:
			return
		diff = block.seqno - prev_block.seqno
		for i in range(diff-1, 0, -1):
			#self._start_thread(self._search_block, block.workchain, block.shard, block.seqno - i)
			#self._search_block(block.workchain, block.shard, block.seqno - i)
			if block.workchain < 0:
				self._start_thread_with_queue(self._search_block, block.workchain, block.shard, block.seqno - i)
			else:
				self._search_block(block.workchain, block.shard, block.seqno - i)
	#end define

	def _search_block(self, workchain, shard, seqno):
		#self._add_log(f"_search_block ({workchain},{shard},{seqno})")
		block = self._try_with_exception(self.adnl.lookup_block, workchain, shard, seqno)
		if block.workchain < 0:
			self._read_master_block(block)
		else:
			self._read_shard_block(block)
	#end define

	def _get_shard_prev_block(self, shard):
		prev_block = self.prev_shards_block.get(shard)
		return prev_block
	#end define

	def _set_shard_prev_block(self, prev_block):
		self.prev_shards_block[prev_block.shard] = prev_block
	#end define

	def _new_block_reaction(self, block):
		#print(f"{bcolors.green} block: {bcolors.endc} {block}")
		self.blocks_num += 1
		if self.nbr:
			self._start_thread(self.nbr, block)
		transactions = self._try_with_exception(self.adnl.get_block_transactions, block)
		#print(f"{bcolors.green} block: ({block.workchain},{block.shard},{block.seqno}) -> {len(transactions)} transactions {bcolors.endc}")
		for trans in transactions:
			self._start_thread(self._new_trans_reaction, block, trans)
	#end define

	def _new_trans_reaction(self, block, trans):
		#print(f"{bcolors.magenta} trans: {bcolors.endc} {trans}")
		self.trans_num += 1
		if self.ntr:
			self._start_thread(self.ntr, block, trans)
		if self.skip_messages == True:
			return
		#end if
		
		messages = self._try_with_exception(self.adnl.get_messages_from_transaction, block, trans)
		for message in messages:
			self._start_thread(self._new_message_reaction, block, trans, message)
	#end define

	def _new_message_reaction(self, block, trans, message):
		self.messages_num += 1
		if self.nmr:
			self._start_thread(self.nmr, block, trans, message)
		#print(f"{bcolors.yellow} message: {bcolors.endc} {message}")
	#end define
#end class