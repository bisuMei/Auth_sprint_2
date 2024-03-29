"""App constants."""
from dataclasses import dataclass
from datetime import date, timedelta

BASE_DATE = date.min.strftime('%Y-%m-%d')

GOOGLE_OAUTH = 'google'
OAUTH_PROVIDERS = {
    GOOGLE_OAUTH: 'google',
}

DEFAULT_TTL = timedelta(hours=1)

SUPERUSER_ROLE = 'SUPERUSER'
SUPERUSER_PERMISSIONS = {
    'ALL_PERMISSION': {
        'read': True,
        'create': True,
        'update': True,
        'delete': True,
    }
}

DEFAULT_ROLE = 'USER'
DEFAULT_PERMISSIONS = {
    'MOVIES': {
        'create': False,
        'read': True,
        'update': False,
        'delete': False,
    },
}


@dataclass
class ResponseMessage:
    SUCCESS = 'Success'
    MISSED_FIELDS = ' Missed fields'
    INVALID_CREDENTIALS = 'Invalid Credentials!'
    USER_EXISTS = 'User with login alredy exists'
    ROLE_EXISTS = 'Role with provides data already exists.'
    REVOKED_TOKEN = 'Access token revoked'
    INVALID_USER_ROLE = 'Invalid user or role id'
    OBJECT_NOT_FOUND = 'Object not found'
    SUPERUSER_ONLY = 'Superuser only!'
    USE_REFRESH_TOKEN = 'Please use refresh token related to current user.'
    TOO_MANY_REQUESTS = 'Too many requests from user.'
