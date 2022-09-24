import json
import traceback

from adnl import Adnl

from config import Config
from settings import Settings 


if __name__ == '__main__':
    web_config = Config(Settings().CONFIG_URL)
    parsed_config = web_config.get()

    servers_count = len(parsed_config.lite_servers)
    
    for i in range(servers_count):
        print(i, end='. ')
        c_host = parsed_config.lite_servers[i].ipv4
        c_port = parsed_config.lite_servers[i].port
        c_pubkey = parsed_config.lite_servers[i].server_id.key
        try:
            print(c_host, c_port)
            with Adnl(c_host, c_port, c_pubkey) as adnl:
                adnl.ping()
                data = adnl.get_masterchain_info()
                print(json.dumps(data, indent=4))
                break
        except Exception as ex:
            print(ex)
            traceback.print_exc()
