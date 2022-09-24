from pydantic import Field
from pydantic import BaseModel

from .server_id import ServerId


class LiteserverConfig(BaseModel):
    ip: int
    port: int
    server_id: ServerId = Field(alias='id')

    @property
    def ipv4(self) -> str:
        domains = []
        for domain in range(24, -8, -8):
            if domain:
                domains.append(str((self.ip >> domain) & 0xFF))
            else:
                domains.append(str(self.ip & 0xFF))
        return '.'.join(domains)

    @property
    def connection_str(self):
        return f"{self.ipv4}:{self.port}"
