from http import HTTPStatus

from flask import jsonify
from flask_restx import Namespace, Resource

from app.main import oauth_config
from app.main.constants import OAUTH_PROVIDERS
from app.main.service.oauth import oauth, OauthService


api = Namespace('Oauth', description='Login, logout, register user with social service.')


@api.route("/oauth/login/<string:provider_name>/")
class OauthLogin(Resource):

    @api.doc(description="Authenticate with social network account")
    def get(self, provider_name: str):
        if allowed_provider := OAUTH_PROVIDERS.get(provider_name):
            client = oauth.create_client(allowed_provider)
            return client.authorize_redirect(oauth_config.REDIRECT_URI)

        response = jsonify(message=f"Provided social service {provider_name} not allowed")
        response.status_code = HTTPStatus.NOT_FOUND
        return response


@api.route("/oauth/<string:provider_name>/")
class OauthAuthorization(Resource):

    @api.doc(description="Redirect endpoint after service auth. Return pair of access/refresh token.")
    def get(self, provider_name: str):

        allowed_provider = OAUTH_PROVIDERS.get(provider_name)

        client = oauth.create_client(allowed_provider)
        token = client.authorize_access_token()
        user_info = token.get("userinfo")

        if not user_info:
            user_info = client.userinfo()

        service = OauthService(user_info)

        return service.login_user()
