import json
from mytonlib import Adnl

from config import Config
from settings import Settings

if __name__ == '__main__':
    web_config = Config(Settings().CONFIG_URL)
    parsed_config = web_config.get()

    servers_count = len(parsed_config.lite_servers)

    for i in range(servers_count):
        c_host = parsed_config.lite_servers[i].ipv4
        c_port = parsed_config.lite_servers[i].port
        c_pubkey = parsed_config.lite_servers[i].server_id.key
        try:
            with Adnl(c_host, c_port, c_pubkey) as adnl:
                adnl.Ping()
                data = adnl.GetMasterchainInfo()
                print(json.dumps(data, indent=4))
                break
        except Exception as ex:
            print(ex)
