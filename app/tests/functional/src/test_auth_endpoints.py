import json
from http import HTTPStatus

from flask import jsonify

from app.main.model.users import User
from app.main.model.profile import Profile
from app.main.model.user_auth_data import UserAuthData
from app.main.service.db import db_session


def test_register_user(
    client, 
    api_v1_user_register, 
    load_test_user_for_register,
):
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    response = client.post(
        api_v1_user_register, 
        data=json.dumps(load_test_user_for_register), 
        headers=headers)

    user = User.query.filter_by(login=load_test_user_for_register.get('login')).one_or_none()
    Profile.query.filter_by(user_id=user.id).delete()
    User.query.filter_by(login=load_test_user_for_register.get('login')).delete()
    db_session.commit()
    
    assert response.content_type == mimetype
    assert response.json['message'] == "Success"
    assert response.status_code == HTTPStatus.OK

    
def test_login(
    client,
    api_v1_user_register, 
    load_test_user_for_register, 
    api_v1_user_login,
    user_for_test,
):
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    response = client.post(
        api_v1_user_login, 
        data=json.dumps(
            {
                "login": load_test_user_for_register['login'],
                "password": load_test_user_for_register['password'],
            }
        ),
        headers=headers,
    )

    assert response.content_type == mimetype    
    assert response.json.get('access_token') != None
    assert response.json.get('refresh_token') != None
    assert response.status_code == HTTPStatus.OK


def test_logout(
    client,
    api_v1_user_logout,
    api_v1_user_register, 
    load_test_user_for_register, 
    api_v1_user_login,
    load_test_user_login_data,
    user_for_test,
):
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    response = client.post(
        api_v1_user_login,
        data=json.dumps(
            {
                "login": load_test_user_for_register['login'],
                "password": load_test_user_for_register['password'],
            }
        ),
        headers=headers,
    )
        
    headers_prot = {
        'Authorization': f'Bearer {response.json.get("access_token")}',
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    response = client.post(
        api_v1_user_logout, 
        headers=headers_prot,
    )
    
    assert response.content_type == mimetype    
    assert response.json['message'] == "Access token revoked"
    assert response.status_code == HTTPStatus.OK
    

def test_user_history(
    client,
    api_v1_user_history,
    api_v1_user_register, 
    load_test_user_for_register, 
    api_v1_user_login,
    load_test_user_login_data,
    user_for_test,
):
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    response = client.post(
        api_v1_user_login,
        data=json.dumps(
            {
                "login": load_test_user_for_register['login'],
                "password": load_test_user_for_register['password'],
            }
        ),
        headers=headers,
    )

    headers_prot = {
        'Authorization': f'Bearer {response.json.get("access_token")}',
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_auth_data = UserAuthData.query.filter_by(user_id=user_for_test.id).one_or_none()
    response = client.get(
        api_v1_user_history.format(user_id=user_for_test.id),
        headers=headers_prot,
    )
    expected_response = jsonify({
            'created_at': user_auth_data.created_at,
            'id': user_auth_data.id,
            'user_agent': user_auth_data.user_agent,
        })
    assert response.status_code == HTTPStatus.OK
    assert response.json == [expected_response.json]
