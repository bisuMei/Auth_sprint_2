from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jti
from flask_restx import Namespace, Resource

from app.main import oauth_config
from app.main.config import config
from app.main.model.roles import Role
from app.main.model.users import User
from app.main.constants import GOOGLE_OAUTH, BASE_DATE
from app.main.service.db import db_session
from app.main.service.oauth import oauth
from app.main.service.cache import jwt_redis_cache
from app.main.utils import insert_auth_data, create_user_profile

api = Namespace('Oauth', description='Login, logout, register user with social service.')


@api.route("/oauth/login/")
class OauthLogin(Resource):

    @api.doc(description="Authenticate with google network account")
    def get(self):
        client = oauth.create_client(GOOGLE_OAUTH)
        return client.authorize_redirect(oauth_config.REDIRECT_URI)


@api.route("/oauth/google/")
class OauthAuthorization(Resource):

    @api.doc(description="Redirect endpoint after google auth. Return pair of access/refresh token.")
    def get(self):

        client = oauth.create_client(GOOGLE_OAUTH)
        token = client.authorize_access_token()
        user_info = token.get("userinfo")

        if not user_info:
            user_info = client.userinfo()

        user_data = {
            "login": user_info['email'],
            "password": user_info['sub'],
            "email": user_info["email"],
            "name_first": user_info["given_name"],
            "name_last": user_info["family_name"],
            "birth_date": BASE_DATE,
        }
        user = User.query.filter_by(login=user_data['login']).one_or_none()
        if not user:
            user = User(**user_data)
            user.roles.append(Role.query.filter_by(default=True).first())
            db_session.add(user)
            db_session.commit()

            create_user_profile(user, user_data)

        if user and user.check_password(user.login, user_data.get('password')):
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
