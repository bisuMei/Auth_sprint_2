from functools import wraps
from http import HTTPStatus

from flask import jsonify
from flask_jwt_extended import current_user, get_jwt, verify_jwt_in_request

from app.main.constants import SUPERUSER_PERMISSIONS, ResponseMessage
from app.main.model.roles import Role
from app.main.service.cache import jwt_redis_cache


def check_refresh_token_current_user():
    """
    Decorator to check if current user has refresh token.

    Check refresh token in cache by user identify and compare jti.
    If exist, means that refresh token not used and new access token can be set for this user.
    Clean refresh token from cache.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            claims = get_jwt()
            stored_jti = jwt_redis_cache.get(str(current_user.id))
            if stored_jti == claims['jti']:
                jwt_redis_cache.delete(str(current_user.id))
                return fn(*args, **kwargs)
            else:
                response = jsonify(message=ResponseMessage.USE_REFRESH_TOKEN)
                response.status_code = HTTPStatus.UNAUTHORIZED
                return response

        return decorator

    return wrapper


def superuser_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()

            if SUPERUSER_PERMISSIONS in claims.get('perms'):
                return fn(*args, **kwargs)
            else:
                response = jsonify(message=ResponseMessage.SUPERUSER_ONLY)
                response.status_code = HTTPStatus.FORBIDDEN
                return response

        return decorator

    return wrapper


def db_helper():
    """Create default role with default permissions after db init."""
    Role.insert_role()
