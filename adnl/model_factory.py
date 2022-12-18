import os
from . import const
from . import crypto
from .tl_object import models

DEBUG = True if os.environ.get('DEBUG') else False

SCHEMAS_MODELS = {
    const.SCHEMA_GET_MASTERCHAIN: models.MasterchainInfo
}


class ModelFactory:
    def __init__(self):
        self.debug = DEBUG
        self.models = {
            crypto.crc32(schema_id): SCHEMAS_MODELS[schema_id]
            for schema_id in SCHEMAS_MODELS
        }

    def get(self, schema_id: bytes) -> models.TLMetaObject:
        model = self.models.get(schema_id)
        if not model:
            raise Exception(f'Model not found [{schema_id}]')
        return model
