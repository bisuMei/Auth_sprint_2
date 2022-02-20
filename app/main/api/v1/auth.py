from http import HTTPStatus

import opentracing
from flask import jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    current_user,
    get_jwt,
    get_jti,
    jwt_required,
)
from flask_restx import Namespace, Resource, fields, reqparse
from sqlalchemy.exc import IntegrityError

from app.main.config import config
from app.main.constants import ResponseMessage
from app.main.model.roles import Role
from app.main.model.users import User
from app.main.model.user_auth_data import UserAuthData
from app.main.service.cache import jwt_redis_cache
from app.main.service.db import db_session
from app.main.service.tracer_service import tracer
from app.main.utils import check_refresh_token_current_user, superuser_required, insert_auth_data, create_user_profile

api = Namespace('Users', description='Login, logout, register user')


@api.route('/user/register')
class UserRegister(Resource):

    user_model = api.model('User', {
        'login': fields.String(required=True, description='User login'),
        'password': fields.String(required=True, description='User password'),
        'email': fields.String(required=True, description='User email'),
        'name_first': fields.String(description='User name'),
        'name_last': fields.String(description='User last name'),
        'birth_date': fields.Date(description="User birth date", default="1990-10-08")
    })

    # validation makes with @api.expect(validate=True) decorator
    @api.response(HTTPStatus.OK.value, ResponseMessage.SUCCESS)
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.USER_EXISTS)
    @api.doc(body=user_model, description="Register new user")
    @api.expect(user_model, validate=True)
    def post(self):
        request_id = request.headers.get('X-Request-Id')                          
        parent_span = tracer.get_span()
        with opentracing.tracer.start_span('retister', child_of=parent_span) as span:
            span.set_tag('http.request_id', request_id)

        try:
            with opentracing.tracer.start_span('create-new-user', child_of=parent_span) as span:                
                user = User(**api.payload)
                user.roles.append(Role.query.filter_by(default=True).first())
                db_session.add(user)
                db_session.commit()

                create_user_profile(user, api.payload)
                span.set_tag('user', user)
        except IntegrityError:
            response = jsonify(message=ResponseMessage.USER_EXISTS)
            response.status_code = HTTPStatus.NOT_FOUND
            return response

        return jsonify(message=ResponseMessage.SUCCESS)


@api.route('/user/login')
class UserLogin(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('login', type=str)
    parser.add_argument('password', type=str)
    user_login_fields = api.model('UserLogin', {
        'login': fields.String(required=True),
        'password': fields.String(required=True),
    })

    @api.response(HTTPStatus.OK.value, "{access_token: jwt_access_token, refresh_token: jwt_refresh_token}")
    @api.response(HTTPStatus.UNAUTHORIZED.value, ResponseMessage.INVALID_CREDENTIALS)
    @api.doc(body=user_login_fields, description="Login into account")
    @api.expect(user_login_fields, validate=True)    
    def post(self):
        request_id = request.headers.get('X-Request-Id')                          
        parent_span = tracer.get_span()
        with opentracing.tracer.start_span('login', child_of=parent_span) as span:
            span.set_tag('http.request_id', request_id)
            
        with opentracing.tracer.start_span('get-user-db', child_of=parent_span) as span:
            data = self.parser.parse_args()
            user = User.query.filter_by(login=data.get('login')).one_or_none()
            span.set_tag('user.login', user)

        with opentracing.tracer.start_span('tokens') as span:
            if user and user.check_password(user.login, data.get('password')):
                permissions = user.get_all_permissions()
                access_token = create_access_token(
                    identity=user.id,
                    fresh=True,
                    additional_claims={'perms': permissions}
                )
                refresh_token = create_refresh_token(user.id, additional_claims={'perms': permissions})

                insert_auth_data(user)

                jwt_redis_cache.set(
                    str(user.id), 
                    get_jti(refresh_token), 
                    ttl=config.JWT_REFRESH_TOKEN_EXPIRES
                )
                return jsonify(access_token=access_token, refresh_token=refresh_token)

            response = jsonify(message=ResponseMessage.INVALID_CREDENTIALS)
            response.status_code = HTTPStatus.UNAUTHORIZED
            return response


@api.response(HTTPStatus.OK.value, ResponseMessage.REVOKED_TOKEN)
@api.doc(description="Logout from account. Expected access jwt token into headers.")
@api.route('/user/logout')
class UserLogout(Resource):

    @api.doc("Logout. Access token into headers is required.")
    @jwt_required(locations='headers')
    def post(self):        
        jti = get_jwt()["jti"]
        jwt_redis_cache.set(jti, "", ttl=config.JWT_ACCESS_TOKEN_EXPIRES)
        return jsonify(message=ResponseMessage.REVOKED_TOKEN)


@api.route('/user/refresh')
class RefreshToken(Resource):

    @jwt_required(refresh=True)
    @check_refresh_token_current_user()
    @api.doc(description="Refresh token. Refresh token into headers is required.")
    @api.response(HTTPStatus.OK.value, "{access_token: jwt_access_token, refresh_token: jwt_refresh_token}")
    def post(self):
        request_id = request.headers.get('X-Request-Id')                          
        parent_span = tracer.get_span()
        with opentracing.tracer.start_span('refresh-token', child_of=parent_span) as span:
            span.set_tag('http.request_id', request_id)

        with opentracing.tracer.start_span('get-permissions', child_of=parent_span) as span:            
            permissions = current_user.get_all_permissions()
            span.set_tag('permissions', permissions)

        with opentracing.tracer.start_span('access-refresh-token', child_of=parent_span) as span:            
            access_token = create_access_token(
                identity=current_user.id,
                fresh=True,
                additional_claims={'perms': permissions}
            )
            span.set_tag('access-token', access_token)

            refresh_token = create_refresh_token(current_user.id, additional_claims={'perms': permissions})
            span.set_tag('refresh-token', refresh_token)

        jwt_redis_cache.set(str(current_user.id), get_jti(refresh_token), ttl=config.JWT_REFRESH_TOKEN_EXPIRES)
        return jsonify(access_token=access_token, refresh_token=refresh_token)


@api.route('/user/<user_id>')
class UpdateUser(Resource):

    user_model = api.model('UserUpdate', {
        'login': fields.String(required=True, description='User login'),
        'password': fields.String(required=True, description='User password'),
        'email': fields.String(required=True, description='User email'),
        'name_first': fields.String(description='User name'),
        'name_last': fields.String(description='User last name'),
        'birth_date': fields.String(description='User birth date'),
    })

    @api.response(HTTPStatus.OK.value, ResponseMessage.SUCCESS)
    @api.response(HTTPStatus.NOT_FOUND.value, ResponseMessage.OBJECT_NOT_FOUND)
    @api.doc(body=user_model, description="Update user data. Access token into headers is required.")
    @jwt_required(locations='headers')
    @api.expect(user_model, validate=True)
    def patch(self, user_id):
        request_id = request.headers.get('X-Request-Id')
        parent_span = tracer.get_span()
        with opentracing.tracer.start_span('update-user-data', child_of=parent_span) as span:
            span.set_tag('http.request_id', request_id)

        with opentracing.tracer.start_span('get-user', child_of=parent_span) as span:            
            user = User.query.get(user_id)
            if user:
                user.patch(api.payload)
                db_session.commit()
                span.set_tag('user-updated', user)
                return jsonify(message=ResponseMessage.SUCCESS)

        response = jsonify(message=f"user {user_id} not found")
        response.status_code = HTTPStatus.NOT_FOUND
        return response


@api.route('/user/<user_id>/auth_history')
class UserHistory(Resource):

    user_auth_model = api.model('UserAuth', {
        'id': fields.String(),
        'user_agent': fields.String(),
        'created_at': fields.String(),
    })

    @api.response(HTTPStatus.OK.value, description="User auth", model=user_auth_model)
    @api.doc(description="History user data. Access token into headers is required.")
    @jwt_required(locations='headers')
    def get(self, user_id):
        request_id = request.headers.get('X-Request-Id')
        parent_span = tracer.get_span()
        with opentracing.tracer.start_span('get-auth-history', child_of=parent_span) as span:
            span.set_tag('http.request_id', request_id)

        with opentracing.tracer.start_span('get-history', child_of=parent_span) as span:            
            user_data = UserAuthData.query.filter_by(user_id=user_id)
            history = [{
                'id': usr.id,
                'user_agent': usr.user_agent,
                'created_at': usr.created_at
                } for usr in user_data
            ]
            span.set_tag('user-auth-history', history)
        return jsonify(history)


@api.route('/user/permission')
class PermissionUserRole(Resource):

    permission_model = api.model('Permission', {
        'create': fields.Boolean(),
        'read': fields.Boolean(),
        'update': fields.Boolean(),
        'delete': fields.Boolean(),
    })

    parser = reqparse.RequestParser()
    parser.add_argument('user_id', type=str, required=True)
    parser.add_argument('role_name', type=str, required=True)
    parser.add_argument('permission_name', type=str, required=True)

    @jwt_required()
    @superuser_required()
    @api.response(HTTPStatus.OK.value, description="Permission response", model=permission_model)
    @api.response(HTTPStatus.NOT_FOUND.value, "Object with {user_id} does not exist")
    @api.doc(
        description='Set role to user',
        params={'user_id': 'User id', 'role_name': "Role name", 'permission_name': "Permission name"},
    )
    @api.expect(parser, validate=True)
    def get(self):
        args = self.parser.parse_args()
        if user := User.query.filter_by(id=args['user_id']).one_or_none():
            return jsonify(user.user_permissions_by_role(args['role_name'], args['permission_name']))

        response = jsonify(f"Object with {args['user_id']} does not exists")
        response.status_code = HTTPStatus.NOT_FOUND
        return response
