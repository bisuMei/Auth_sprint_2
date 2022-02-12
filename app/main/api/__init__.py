from flask_restx import Api

from app.main.api.v1.auth import api as auth_api
from app.main.api.v1.perms import api as role_api

api = Api(
    version="1.0",
    title="User API for personal account",
    description="API for the website and personal account"
)

api.add_namespace(auth_api, path='/api/v1')
api.add_namespace(role_api, path='/api/v1')
