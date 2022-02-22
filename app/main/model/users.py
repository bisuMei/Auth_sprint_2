import hashlib
import hmac
import uuid

from typing import Union

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, backref

from app.main.config import config
from app.main.service.db import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    login = Column(String(100), nullable=False, unique=True)
    password = Column(String(150), nullable=False)
    user_auth_data = relationship('UserAuthData')
    profile = relationship('Profile')
    roles = relationship('Role', secondary='user_roles', backref=backref('users', lazy='dynamic'))

    def __init__(self, login, password, email, name_first, name_last, birth_date):
        self.login = login
        self.password = self._set_password(password)
        self.profile.user_id = self.id
        self.profile.email = email
        self.profile.name_first = name_first
        self.profile.name_last = name_last
        self.profile.birth_date = birth_date

    def __repr__(self):
        return f'<User {self.login}>' 

    def _set_password(self, password: str) -> str:
        return self._sign_data(self.login + password)
    
    def _sign_data(self, data: str) -> str:
        """Retern signed data"""

        return hmac.new(
                config.SECRET_PASS_KEY.encode(),
                msg=data.encode(),
                digestmod=hashlib.sha256
            ).hexdigest().upper()

    def user_permissions_by_role(self, role: str, permission_name: str) -> Union[dict, str]:
        """Get CRUD permission by role name and permission name."""
        for user_role in self.roles:
            if user_role.name == role and user_role.permissions.get(permission_name):
                return user_role.permissions.get(permission_name)
        return f'User with id {self.id} does not have this permissions.'

    def get_all_permissions(self):
        return [{role.name: role.permissions} for role in self.roles]

    def check_password(self, login: str, password: str) -> bool:
        valid_sign = self._sign_data(login + password)
        return hmac.compare_digest(valid_sign, self.password)

    def patch(self, kwargs):
        for column_name in User.__table__.columns:
            key = str(column_name).split('.')[-1]
            value = kwargs.get(key)
            if value and key == 'password':
                self.password = self._set_password(value)
            elif value and hasattr(self, key):
                setattr(self, key, value)
