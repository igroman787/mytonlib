import json
import requests
from config_types import GlobalConfig


class Config:
    def __init__(self, url: str):
        self.url = url

    def get(self) -> GlobalConfig:
        response = requests.get(self.url)
        response.raise_for_status()
        try:
            return GlobalConfig.parse_raw(response.text)
        except Exception as ex:
            print(ex)
            raise ex