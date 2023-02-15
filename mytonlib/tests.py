#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import json
from .adnl import AdnlTcpClient, AdnlUdpClient



def tests():
	"""
	Test commands from lite-client
	"""
	
	host = "185.86.79.9"
	port = 4701
	pubkey = "G6cNAr6wXBBByWDzddEWP5xMFsAcp6y13fXA8Q7EJlM="

	adnl = AdnlTcpClient()
	adnl.connect(host, port, pubkey)
	adnl.ping()

	# time - Get server time
	data = adnl.get_time()
	print("get_time:", json.dumps(data, indent=4))

	# last - Get last block and state info from server
	mc_info = adnl.get_masterchain_info()
	print("get_masterchain_info:", json.dumps(mc_info, indent=4))
	print(f"mc_info.last.seqno: {mc_info.last.seqno}")

	# getaccount - Loads the most recent state of specified account
	data = adnl.get_account_state("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N")
	print("get_account_state:", json.dumps(data, indent=4))
	
	# runmethod - Runs GET method <method-id> of account <addr> with specified parameters
	data = adnl.run_smc_method("kQBL2_3lMiyywU17g-or8N7v9hDmPCpttzBPE2isF2GTziky", "mult", [5, 4])
	print("run_smc_method_1:", json.dumps(data, indent=4))
	data = adnl.run_smc_method("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", "seqno")
	print("run_smc_method_2:", json.dumps(data, indent=4))
	data = adnl.run_smc_method("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", "get_public_key")
	print("run_smc_method_3:", json.dumps(data, indent=4))
	
	# dnsresolve - Resolves a domain starting from root dns smart contract
	#*
	
	# dnsresolvestep - Resolves a subdomain using dns smart contract <addr>
	
	
	# allshards - Shows shard configuration from the most recent masterchain state or from masterchain state corresponding to <block-id-ext>
	data = adnl.get_all_shards_info()
	print("get_all_shards_info:", json.dumps(data, indent=4))
	
	# getconfig [<param>...]  Shows specified or all configuration parameters from the latest masterchain state
	data = adnl.get_config_params(4)
	print("get_config_params:", json.dumps(data, indent=4))
	
	# gethead - Shows block header for <block-id-ext>
	data = adnl.get_block_header()
	print("get_block_header:", json.dumps(data, indent=4))
	
	# getblock - Downloads block
	block_info = adnl.get_block()
	print("get_block:", json.dumps(block_info, indent=4))
	
	# DELETE
	# getstate - Downloads state corresponding to specified block
	#data = adnl.get_state()
	#print("get_state:", json.dumps(data, indent=4))
	#print("get_state:", data)
	
	# lasttrans - Shows or dumps specified transaction and several preceding ones
	data = adnl.get_last_transactions("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", 1)
	print("get_last_transactions:", json.dumps(data, indent=4))
	
	# listblocktrans - Lists block transactions, starting immediately after or before the specified one
	block_trans = adnl.get_block_transactions(mc_info.last)
	print("get_block_transactions:", json.dumps(block_trans, indent=4))
	
	# dumptrans - Dumps one transaction of specified account
	account_id = {"workchain": mc_info.last.workchain, "id": block_trans[0].account}
	data = adnl.get_one_transaction(mc_info.last, account_id, block_trans[0].lt)
	print("get_one_transaction:", json.dumps(data, indent=4))
	
	# byseqno - Looks up a block by workchain, shard and seqno, and shows its header
	data = adnl.lookup_block(mc_info.last.workchain, mc_info.last.shard, mc_info.last.seqno-10)
	print("byseqno:", json.dumps(data, indent=4))
	
	# bylt - Looks up a block by workchain, shard and logical time, and shows its header
	data = adnl.lookup_block(mc_info.last.workchain, mc_info.last.shard, lt=block_info.info.start_lt)
	print("bylt:", json.dumps(data, indent=4))
	
	# byutime - Looks up a block by workchain, shard and creation time, and shows its header
	data = adnl.lookup_block(mc_info.last.workchain, mc_info.last.shard, utime=block_info.info.gen_utime-100)
	print("byutime:", json.dumps(data, indent=4))
	
	# creatorstats - Lists block creator statistics by validator public key
	
	
	# recentcreatorstats - Lists block creator statistics updated after <start-utime> by validator public key
	
	
	# checkload - Checks whether all validators worked properly during specified time interval, and optionally saves proofs into <savefile-prefix>-<n>.boc
	#*
	
	# loadproofcheck - Checks a validator misbehavior proof previously created by checkload
	#*
	
	# pastvalsets     Lists known past validator set ids and their hashes
	
	
	# savecomplaints - Saves all complaints registered for specified validator set id into files <filename-pfx><complaint-hash>.boc
	#*
	
	# complaintprice - Computes the price (in nanograms) for creating a complaint
	
	
	# sendfile - Load a serialized message from <filename> and send it to server
	body = bytes.fromhex("b5ee9c7241010101000e0000180000000400000000628f328d83ad456c")
	data = adnl.send_ext_msg(body)
	print("send_ext_msg:", json.dumps(data, indent=4))
#end define

def tests2():
	host = "65.21.7.173"
	port = 15813
	pubkey = "fZnkoIAxrTd4xeBgVpZFRm5SvVvSx7eN3Vbe8c83YMk="
	
	adnl = AdnlUdpClient()
	adnl.connect(host, port, pubkey)
#end defines


###
### Start of the program
###

if __name__ == "__main__":
	tests()
	#tests2()
#end if