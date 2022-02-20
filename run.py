import datetime

import click

from app.main import create_app
from app.main.constants import SUPERUSER_ROLE, SUPERUSER_PERMISSIONS
from app.main.service.db import db_session
from app.main.model.roles import Role
from app.main.model.users import User


app = create_app()


@app.cli.command()
@click.option('--user_login', prompt='Super User login',
              help='The super User name.')
@click.option('--user_password', prompt='Super User password',
              help='The super User password.')
@click.option('--user_name', prompt='User name', default='',
              help='User name.')
@click.option('--user_last_name', prompt='User last name', default='',
              help='User last name.')
@click.option('--user_email', prompt='User email', default='',
              help='User email.')
@click.option('--birth_date', prompt='User birthdate', default='',
              help='User email.')
def createsuperuser(
    user_login: str, 
    user_password: str,
    user_name: str,
    user_last_name: str,
    user_email: str,
    user_birth_date: datetime.date,
) -> None:

    superuser = User(
        user_login,
        user_password,
        user_name,
        user_last_name,
        user_email,
        user_birth_date
    )

    super_role = Role(
        name=SUPERUSER_ROLE,
        permissions=SUPERUSER_PERMISSIONS,
    )

    superuser.roles.append(super_role)

    db_session.add(super_role)
    db_session.add(superuser)
    db_session.commit()    


def run():
    app.run()


if __name__ == '__main__':
    run()
