from http import HTTPStatus

from flask import jsonify, Response
from flask_jwt_extended import jwt_required
from flask_restx import Namespace, Resource, fields, reqparse
from psycopg2 import IntegrityError

from app.main.constants import ResponseMessage
from app.main.model.roles import Role, UserRoles
from app.main.model.users import User
from app.main.service.db import db_session
from app.main.utils import superuser_required


api = Namespace('Roles', description='Create, update, set roles.')


role_model = api.model('Role', {
        'name': fields.String(required=True, description="Role name"),
        'permissions': fields.Raw(
            example={
                "MOVIES": {
                    "create": True,
                    "read": True,
                    "update": True,
                    "delete": False,
                },
                "GENRES": {
                    "create": True,
                    "read": True,
                    "update": True,
                    "delete": False,
                    },
                },
            ),
        })


@api.route('/role/user_role')
class RoleUser(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('user_id', type=str, required=True)
    parser.add_argument('role_id', type=str, required=True)

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.OK.value, ResponseMessage.SUCCESS)
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.INVALID_USER_ROLE)
    @api.doc(description='Set role to user', params={'user_id': "User_id", 'role_id': "Role_id"})
    @api.expect(parser, validate=True)
    def post(self):

        args = self.parser.parse_args()

        role = Role.query.filter_by(id=args['role_id']).one_or_none()
        user = User.query.filter_by(id=args['user_id']).one_or_none()
        if role and user:
            user_roles = UserRoles(role_id=role.id, user_id=user.id)
            db_session.add(user_roles)
            db_session.commit()

            return jsonify(message=ResponseMessage.SUCCESS)

        response = jsonify(message=ResponseMessage.INVALID_USER_ROLE)
        response.status_code = HTTPStatus.NOT_FOUND

        return response

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.NO_CONTENT.value, description="")
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.INVALID_USER_ROLE)
    @api.doc(description='Remove user role.', params={'user_id': "User_id", 'role_id': "Role_id"})
    @api.expect(parser, validate=True)
    def delete(self):

        args = self.parser.parse_args()

        role = Role.query.filter_by(id=args['role_id']).one_or_none()
        user = User.query.filter_by(id=args['user_id']).one_or_none()
        if user and role:
            user_roles = UserRoles.query.filter_by(user_id=user.id, role_id=role.id).one_or_none()
            db_session.delete(user_roles)
            db_session.commit()

            return Response(status=HTTPStatus.NO_CONTENT)

        response = jsonify(message=ResponseMessage.INVALID_USER_ROLE)
        response.status_code = HTTPStatus.NOT_FOUND

        return response


@api.route('/role/<string:role_id>')
class RoleUpdateDelete(Resource):

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.OK.value, ResponseMessage.SUCCESS)
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.OBJECT_NOT_FOUND)
    @api.doc(description='Update role', body=role_model)
    @api.expect(role_model, validate=True)
    def patch(self, role_id):
        if role := Role.query.filter_by(id=role_id).one_or_none():
            role.name = api.payload['name']
            role.permissions = api.payload['permissions']

            db_session.commit()

            return jsonify(message=ResponseMessage.SUCCESS)

        response = jsonify(message=ResponseMessage.OBJECT_NOT_FOUND)
        response.status_code = HTTPStatus.NOT_FOUND

        return response

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.NO_CONTENT.value, description="")
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.OBJECT_NOT_FOUND)
    @api.doc(description='Delete role')
    def delete(self, role_id):

        if role := Role.query.filter_by(id=role_id).one_or_none():
            db_session.delete(role)
            db_session.commit()

            return Response(status=HTTPStatus.NO_CONTENT)

        response = jsonify(message=ResponseMessage.OBJECT_NOT_FOUND)
        response.status_code = HTTPStatus.NOT_FOUND

        return response


@api.route('/role')
class RoleCreate(Resource):

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.OK.value, ResponseMessage.SUCCESS)
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.ROLE_EXISTS)
    @api.doc(description='Create role', body=role_model)
    @api.expect(role_model, validate=True)
    def post(self):
        try:
            role = Role(**api.payload)
            db_session.add(role)
            db_session.commit()
        except IntegrityError:
            response = jsonify(message=ResponseMessage.ROLE_EXISTS)
            response.status_code = HTTPStatus.NOT_FOUND
            return response

        return jsonify(message=ResponseMessage.SUCCESS)

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.OK.value, description="[{role_id, name, permissions}]")
    @api.doc(description='Get roles')
    def get(self):

        roles = [
            {
                'role_id': str(role.id),
                'name': role.name,
                'permissions': role.permissions,
            } for role in db_session.query(Role).all()
        ]
        return jsonify(roles)
