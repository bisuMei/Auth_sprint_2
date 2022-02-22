from abc import ABC
from http import HTTPStatus

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jti

from app.main.service.cache import jwt_redis_cache
from app.main.config import oauth_config, config
from app.main.constants import GOOGLE_OAUTH, BASE_DATE
from app.main.model.roles import Role
from app.main.model.users import User
from app.main.service.db import db_session
from app.main.utils import create_user_profile, insert_auth_data

oauth = OAuth()

oauth.register(name=GOOGLE_OAUTH, client_kwargs={"scope": oauth_config.GOOGLE_OAUTH_SCOPE})


def init_oauth(app: Flask):
    app.config["GOOGLE_CLIENT_ID"] = oauth_config.GOOGLE_CLIENT_ID
    app.config["GOOGLE_CLIENT_SECRET"] = oauth_config.GOOGLE_CLIENT_SECRET
    app.config["GOOGLE_SERVER_METADATA_URL"] = oauth_config.GOOGLE_SERVER_METADATA_URL
    oauth.init_app(app)


class BaseOauthService(ABC):

    def __init__(self, user_info: dict):
        self.user_info = user_info

    def login_user(self):
        raise NotImplementedError


class OauthService(BaseOauthService):

    def login_user(self):
        """Login User by social provider."""
        user = User.query.filter_by(login=self.user_info['email']).one_or_none()
        if not user:
            user_data = {
                "login": self.user_info['email'],
                "password": self.user_info['sub'],
                "email": self.user_info["email"],
                "name_first": self.user_info["given_name"],
                "name_last": self.user_info["family_name"],
                "birth_date": BASE_DATE,
            }
            user = User(**user_data)
            user.roles.append(Role.query.filter_by(default=True).first())
            db_session.add(user)
            db_session.commit()

            create_user_profile(user, user_data)

        if user and user.check_password(user.login, self.user_info['sub']):
            permissions = user.get_all_permissions()
            access_token = create_access_token(
                identity=user.id,
                fresh=True,
                additional_claims={'perms': permissions}
            )
            refresh_token = create_refresh_token(user.id, additional_claims={'perms': permissions})

            jwt_redis_cache.set(
                str(user.id),
                get_jti(refresh_token),
                ttl=config.JWT_REFRESH_TOKEN_EXPIRES
            )

            insert_auth_data(user)

            return jsonify(access_token=access_token, refresh_token=refresh_token)

        response = jsonify(message=f"Can not login by provided info for {self.user_info['email']}")
        response.status_code = HTTPStatus.NOT_FOUND
        return response
