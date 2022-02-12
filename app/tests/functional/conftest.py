import json
from pathlib import Path

import pytest

from app.main import create_app
from app.main.constants import SUPERUSER_ROLE, SUPERUSER_PERMISSIONS
from app.main.model.user_auth_data import UserAuthData
from app.main.model.users import User
from app.main.model.roles import Role
from app.main.service.db import db_session

pytest_plugins = (
    "app.tests.functional.utils.roles_conftest",
    "app.tests.functional.utils.auth_conftest",
)

BASE_DIR = Path(__file__).resolve().parent


@pytest.fixture()
def client():
    app = create_app()

    app.config["TESTING"] = True
    app.testing = True

    with app.app_context():
        with app.test_client() as client:
            yield client


@pytest.fixture
def load_test_data():
    def load_data(filename: str):
        with open(BASE_DIR / 'testdata' / filename) as file:  
            return json.load(file)          
    return load_data


@pytest.fixture
def user_for_test(load_test_user_for_register):

    user = User(**load_test_user_for_register)
    role = Role(
        name=SUPERUSER_ROLE,
        permissions=SUPERUSER_PERMISSIONS,
    )
    user.roles.append(role)

    db_session.add(user)
    db_session.add(role)
    db_session.commit()
    yield user
    UserAuthData.query.filter_by(user_id=user.id).delete()
    db_session.delete(user)
    db_session.delete(role)
    db_session.commit()


@pytest.fixture
def client_login(client, user_for_test, api_v1_user_login, load_test_user_for_register):
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    response = client.post(
        api_v1_user_login,
        data=json.dumps(
            {
                "login": load_test_user_for_register['login'],
                "password": load_test_user_for_register['password'],
            }
        ),
        headers=headers,
    )
    yield response.json.get("access_token")
