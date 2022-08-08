from pydantic import BaseSettings


class Settings(BaseSettings):
    CONFIG_URL: str

    class Config:
        env_file = '.env'
