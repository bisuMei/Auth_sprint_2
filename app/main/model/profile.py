import uuid
from sqlalchemy import Column, String, Date, UniqueConstraint, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.main.service.db import Base


def create_partition(target, connection, **kw) -> None:
    """ creating partition by user birth_date."""
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_born_1990_2000" PARTITION OF "profile" FOR VALUES FROM ('1990-01-01') TO ('2000-01-01')"""  # noqa E501
    )
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_born_2000_2010" PARTITION OF "profile" FOR VALUES FROM ('2000-01-01') TO ('2010-01-01')"""  # noqa E501
    )
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS "user_born_2010_2020" PARTITION OF "profile" FOR VALUES FROM ('2010-01-01') TO ('2020-01-01')"""  # noqa E501
    )


class Profile(Base):
    __tablename__ = 'profile'

    __table_args__ = (
        UniqueConstraint('id', 'birth_date'),
        {
            'postgresql_partition_by': 'RANGE (birth_date)',
            'listeners': [('after_create', create_partition)],
        }
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    email = Column(String(100), nullable=False)
    name_first = Column(String(100), nullable=False)
    name_last = Column(String(100), nullable=False)
    birth_date = Column(Date(), nullable=False, primary_key=True)

    def __init__(self, user_id, email, name_first, name_last, birth_date):
        self.user_id = user_id
        self.email = email
        self.name_first = name_first
        self.name_last = name_last
        self.birth_date = birth_date
