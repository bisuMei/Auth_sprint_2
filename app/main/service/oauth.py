from authlib.integrations.flask_client import OAuth
from flask import Flask
from app.main.config import oauth_config
from app.main.constants import GOOGLE_OAUTH

oauth = OAuth()

oauth.register(name=GOOGLE_OAUTH, client_kwargs={"scope": oauth_config.GOOGLE_OAUTH_SCOPE})


def init_oauth(app: Flask):
    app.config["GOOGLE_CLIENT_ID"] = oauth_config.GOOGLE_CLIENT_ID
    app.config["GOOGLE_CLIENT_SECRET"] = oauth_config.GOOGLE_CLIENT_SECRET
    app.config["GOOGLE_SERVER_METADATA_URL"] = oauth_config.GOOGLE_SERVER_METADATA_URL
    oauth.init_app(app)

