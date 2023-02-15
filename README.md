## What is it?
This is a native library for working with The Open Network.  without using libtonlibjson.

## Installation
```sh
pip3 install mytonlib
```

## How to use
```python
from mytonlib import AdnlTcpClient

# Take public lite-server from https://ton-blockchain.github.io/global.config.json
host = "185.86.79.9"
port = 4701
pubkey = "G6cNAr6wXBBByWDzddEWP5xMFsAcp6y13fXA8Q7EJlM="

# Connect to the lite-server with adnl
adnl = AdnlTcpClient()
adnl.connect(host, port, pubkey)

# Test connection
adnl.ping()

# Get masterchain info
adnl.get_masterchain_info()
```

## List of available functions
All available functions are taken from lite-client
```python
connect 				# Connect to the lite-server with adnl
ping 					# Test connection
get_time 				# Get server time
get_masterchain_info 	# Get last block and state info from server
get_account_state		# Loads the most recent state of specified account
run_smc_method			# Runs GET method <method-id> of account <addr> with specified parameters
get_all_shards_info		# Shows shard configuration from the most recent masterchain state or from masterchain state corresponding to <block-id-ext>
get_config_params		# Shows specified or all configuration parameters from the latest masterchain state
get_block_header		# Shows block header for <block-id-ext>
get_block				# Downloads block
get_last_transactions	# Shows or dumps specified transaction and several preceding ones
get_block_transactions	# Lists block transactions, starting immediately after or before the specified one
get_one_transaction		# Dumps one transaction of specified account
lookup_block			# Looks up a block by workchain, shard and seqno/lt/time, and shows its header
```

## More examples
https://github.com/igroman787/mytonlib/blob/master/tests.py
