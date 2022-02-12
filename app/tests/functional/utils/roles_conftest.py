"""Conftest for roles endpoints."""
import pytest


@pytest.fixture
def role_v1_endpoint():
    return '/api/v1/role'


@pytest.fixture
def role_v1_update_delete_endpoint():
    return '/api/v1/role/{role_id}'


@pytest.fixture
def role_v1_set_user_endpoint():
    return '/api/v1/role/user_role'
