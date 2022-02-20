from functools import wraps
from http import HTTPStatus

from flask import jsonify, request
from flask_jwt_extended import current_user, get_jwt, verify_jwt_in_request

from user_agents import parse

from app.main.constants import SUPERUSER_PERMISSIONS, ResponseMessage
from app.main.model.profile import Profile
from app.main.model.roles import Role
from app.main.model.user_auth_data import UserAuthData, UserDeviceType
from app.main.service.cache import jwt_redis_cache
from app.main.service.db import db_session


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


def insert_auth_data(user: 'User') -> None:
    """Inser user-agent and datetime data into `UserAuthData`."""
    user_agent_raw_data = request.headers.get('User-Agent')
    user_agent = parse(user_agent_raw_data)

    auth_data = {
        "user_id": user.id,
        "user_agent": str(user_agent),
    }
    if user_agent.is_pc:
        auth_data.update({"user_device_type": UserDeviceType.PC.value})
    elif user_agent.is_mobile:
        auth_data.update({"user_device_type": UserDeviceType.MOBILE.value})
    elif user_agent.is_tablet:
        auth_data.update({"user_device_type": UserDeviceType.TABLET.value})
    else:
        auth_data.update({"user_device_type": UserDeviceType.UNKNOWN.value})

    db_session.add(UserAuthData(**auth_data))
    db_session.commit()


def create_user_profile(user: 'User', payload: dict) -> None:
    """Create user profile while register."""
    profile_data = {
        "user_id": user.id,
        "email": payload["email"],
        "name_first": payload["name_first"],
        "name_last": payload["name_last"],
        "birth_date": payload["birth_date"],
    }
    db_session.add(Profile(**profile_data))
    db_session.commit()
