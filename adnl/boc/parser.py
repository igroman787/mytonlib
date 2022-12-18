from adnl import const


class BogParser:
    def __init__(self, hex_str: str):
        self.data = hex_str

    def parse_header(self):
        if self.data.find(const.BOC_HEADER) < 0:
            raise Exception('Not BOC')

        data = self.data.replace(const.BOC_HEADER, '')
        data = bytes.fromhex(data)
