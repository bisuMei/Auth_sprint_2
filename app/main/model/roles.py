import uuid

from sqlalchemy import Column, String, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.main.constants import DEFAULT_PERMISSIONS, DEFAULT_ROLE
from app.main.service.db import Base, db_session


class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = Column(String(50), unique=True)
    permissions = Column(JSONB, default=None)
    default = Column(Boolean, default=False, index=True)  # just use in one case in register user, index faster # noqa: E501

    def __init__(self, **kw):
        super(Role, self).__init__(**kw)
        if self.permissions is None:
            self.permissions = DEFAULT_PERMISSIONS

    @staticmethod
    def insert_role():
        """Create default role after db init."""
        role = Role.query.filter_by(name=DEFAULT_ROLE).first()
        # If there is no such role, add it immediately to facilitate future expansion
        if role is None:
            role = Role(name=DEFAULT_ROLE, permissions=DEFAULT_PERMISSIONS, default=True)

        db_session.add(role)

        db_session.commit()


class UserRoles(Base):
    __tablename__ = "user_roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'))
    role_id = Column(UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'))
