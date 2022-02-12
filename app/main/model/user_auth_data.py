import uuid

from flask_login import UserMixin
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.main.service.db import Base


class UserAuthData(Base, UserMixin):
    __tablename__ = 'users_auth_data'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    user_agent = Column(String, nullable=False)    
    created_at = Column(DateTime(timezone=True), default=func.now())

    def __init__(self, user_id, user_agent):
        self.user_id = user_id
        self.user_agent = user_agent

    