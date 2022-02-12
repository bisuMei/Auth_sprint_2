from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.schema import MetaData

from app.main.config import config


engine = create_engine(config.SQLALCHEMY_DATABASE_URI, convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base(metadata=MetaData(schema=config.POSTGRES_SCHEMA))
Base.query = db_session.query_property() 


def init_db():
    import app.main.model.users
    import app.main.model.user_auth_data
    import app.main.model.roles
    Base.metadata.create_all(bind=engine)
