import json
from abc import ABC
from datetime import timedelta
from typing import Any, Dict, Union

from redis import Redis

from app.main.config import config
from app.main.constants import DEFAULT_TTL


class BaseCache(ABC):
    """Abstract base cache client."""

    def __init__(self, client):
        self.client = client

    def set(self, key: str, value: str, ttl: timedelta) -> Any:
        """Set data to cache db."""
        raise NotImplementedError

    def get(self, key: str, default=None) -> Any:
        """Get data from cache db."""
        raise NotImplementedError

    def delete(self, key: str) -> Any:
        """Delete data from cache db."""
        raise NotImplementedError


class Cache(BaseCache):
    """Redis Cache Client."""

    def set(self, key: str, value: str, ttl: timedelta = DEFAULT_TTL) -> bool:
        return self.client.set(key, json.dumps(value), ex=ttl)

    def get(self, key: str, default=None) -> Union[Dict, None]:
        value = self.client.get(key)
        return json.loads(value.decode('utf-8')) if value else default

    def delete(self, key: str) -> bool:
        return self.client.delete(key)


# use here to avoid of circular import
jwt_redis_cache = Cache(Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB))
