import json
from mytonlib import Adnl

from config import Config
from settings import Settings

if __name__ == '__main__':
    web_config = Config(Settings().CONFIG_URL)
    parsed_config = web_config.get()
    c_host = parsed_config.lite_servers[0].ipv4
    c_port = parsed_config.lite_servers[0].port
    c_pubkey = parsed_config.lite_servers[0].server_id.key

    with Adnl(c_host, c_port, c_pubkey) as adnl:
        adnl.Ping()
        data = adnl.GetMasterchainInfo()
        print(json.dumps(data, indent=4))
