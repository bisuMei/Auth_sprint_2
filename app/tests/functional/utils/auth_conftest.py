"""Fixtures for testing login and registration users."""
import pytest


@pytest.fixture
def load_test_user_for_register(load_test_data):
    return load_test_data('user.json')


@pytest.fixture
def api_v1_user_register():
    return '/api/v1/user/register'


@pytest.fixture
def load_test_user_login_data(load_test_data):
    return load_test_data('login_data.json')


@pytest.fixture
def api_v1_user_login():
    return '/api/v1/user/login'


@pytest.fixture
def api_v1_user_logout():
    return '/api/v1/user/logout'


@pytest.fixture
def api_v1_protected():
    return '/api/v1/protected'


@pytest.fixture
def api_v1_user_history():
    return '/api/v1/user/{user_id}/auth_history'
