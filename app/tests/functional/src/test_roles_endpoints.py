import json
from http import HTTPStatus

from app.main.constants import SUPERUSER_ROLE, SUPERUSER_PERMISSIONS, DEFAULT_PERMISSIONS, DEFAULT_ROLE
from app.main.model.roles import Role, UserRoles
from app.main.service.db import db_session


class TestRolesEndpoints:

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_role = 'TEST_MODERATOR'
    permissions = {
        'GENRES': {
            'create': True,
            'read': True,
            'update': True,
            'delete': False,
        },
    }

    def test_create_role(
        self,
        client,
        client_login,
        role_v1_endpoint,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        response = client.post(
            role_v1_endpoint,
            data=json.dumps(
                {
                    "name": self.user_role,
                    "permissions": self.permissions,
                }
            ),
            headers=self.headers,
        )
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'message': 'Success'}

        role = Role.query.filter_by(name=self.user_role).one_or_none()
        assert role is not None
        assert role.name == self.user_role
        assert role.permissions == self.permissions

        Role.query.filter_by(name=self.user_role).delete()
        db_session.commit()

    def test_get_roles(
        self,
        client,
        client_login,
        role_v1_endpoint,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        response = client.get(role_v1_endpoint, headers=self.headers)
        assert response.status_code == HTTPStatus.OK
        assert response.json == [
            {
                'name': DEFAULT_ROLE,
                'permissions': DEFAULT_PERMISSIONS,
                'role_id': str(Role.query.filter_by(name=DEFAULT_ROLE).first().id),
            },
            {
                'name': SUPERUSER_ROLE,
                'permissions': SUPERUSER_PERMISSIONS,
                'role_id': str(Role.query.filter_by(name=SUPERUSER_ROLE).first().id),
            }
        ]

    def test_update_role(
        self,
        client,
        client_login,
        role_v1_update_delete_endpoint,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        new_name = "SUPER_MODERATOR"
        role = Role.query.filter_by(name=SUPERUSER_ROLE).first()
        response = client.patch(
            role_v1_update_delete_endpoint.format(role_id=str(role.id)),
            data=json.dumps({
                "name": new_name,
                "permissions": self.permissions,
            }),
            headers=self.headers,
        )
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'message': 'Success'}
        assert Role.query.filter_by(name=new_name).one_or_none() is not None

    def test_delete_role(
        self,
        client,
        client_login,
        role_v1_update_delete_endpoint,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        role_name_to_delete = 'DELETE_ME'
        role = Role(
            name=role_name_to_delete,
            permissions=self.permissions,
        )
        db_session.add(role)
        db_session.commit()

        response = client.delete(
            role_v1_update_delete_endpoint.format(role_id=str(role.id)),
            headers=self.headers,
        )
        assert response.status_code == HTTPStatus.NO_CONTENT
        assert Role.query.filter_by(name=role_name_to_delete).one_or_none() is None

    def test_set_user_role(
        self,
        client,
        client_login,
        role_v1_set_user_endpoint,
        user_for_test,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        assert len(user_for_test.roles) == 1
        role_to_set = Role.query.filter_by(default=True).first()

        response = client.post(
            role_v1_set_user_endpoint,
            data=json.dumps({"user_id": str(user_for_test.id), "role_id": str(role_to_set.id)}),
            headers=self.headers,
        )
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'message': 'Success'}
        assert len(user_for_test.roles) == 2
        assert UserRoles.query.filter_by(user_id=user_for_test.id, role_id=role_to_set.id).one_or_none() is not None

    def test_delete_user_role(
        self,
        client,
        client_login,
        role_v1_set_user_endpoint,
        user_for_test,
    ):
        access_token = client_login
        self.headers.update({"Authorization": f"Bearer {access_token}"})

        assert len(user_for_test.roles) == 1
        role_to_delete = UserRoles.query.filter_by(user_id=user_for_test.id).first()

        response = client.delete(
            role_v1_set_user_endpoint,
            data=json.dumps({"user_id": str(user_for_test.id), "role_id": str(role_to_delete.role_id)}),
            headers=self.headers,
        )
        assert response.status_code == HTTPStatus.NO_CONTENT
        assert len(user_for_test.roles) == 0
        assert UserRoles.query.filter_by(user_id=user_for_test.id, role_id=role_to_delete.id).one_or_none() is None
