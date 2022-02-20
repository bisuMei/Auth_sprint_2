import uuid
from enum import Enum

from flask_login import UserMixin
from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.main.service.db import Base


class UserDeviceType(Enum):
    PC = 'PC'
    MOBILE = 'MOBILE'
    TABLET = 'TABLET'
    UNKNOWN = 'UNKNOWN'

    def __str__(self) -> str:
        return str(self.value)


def create_partition(target, connection, **kw) -> None:
    """ creating partition by user_sign_in """
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_auth_data_pc" PARTITION OF "users_auth_data" FOR VALUES IN ('{UserDeviceType.PC.value}')"""  # noqa E501
    )
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_auth_data_mobile" PARTITION OF "users_auth_data" FOR VALUES IN ('{UserDeviceType.MOBILE.value}')"""  # noqa E501
    )
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_auth_data_tablet" PARTITION OF "users_auth_data" FOR VALUES IN ('{UserDeviceType.TABLET.value}')"""  # noqa E501
    )
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_auth_data_unknown" PARTITION OF "users_auth_data" FOR VALUES IN ('{UserDeviceType.UNKNOWN.value}')"""  # noqa E501
    )


class UserAuthData(Base, UserMixin):
    __tablename__ = 'users_auth_data'

    __table_args__ = (
        UniqueConstraint('id', 'user_device_type'),
        {
            'postgresql_partition_by': 'LIST (user_device_type)',
            'listeners': [('after_create', create_partition)],
        }
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    user_agent = Column(String, nullable=False)    
    created_at = Column(DateTime(timezone=True), default=func.now())
    user_device_type = Column(Text, primary_key=True)

    def __init__(self, user_id, user_agent, user_device_type):
        self.user_id = user_id
        self.user_agent = user_agent
        self.user_device_type = user_device_type
