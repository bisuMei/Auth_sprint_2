import datetime
from functools import wraps
from http import HTTPStatus

from flask import jsonify
from flask_jwt_extended import current_user, get_jwt, verify_jwt_in_request
from redis import Redis

from app.main.config import config
from app.main.constants import ResponseMessage


REQUEST_LIMIT_PER_MINUTE = 10


class Bucket:
    """Bucket."""
    
    def __init__(self, redis):        
        self.pipe = redis.pipeline()    

    def rate_limit(self, func):        
        @wraps(func)
        def inner(*args, **kwargs):
            verify_jwt_in_request()

            now = datetime.datetime.now()              
            key = f'{current_user.id}:{now.minute}'
            
            self.pipe.incr(key, 1)    
            self.pipe.expire(key, 59)    
            result = self.pipe.execute()
            
            request_number = result[0]
            
            if request_number > REQUEST_LIMIT_PER_MINUTE:                      
                response = jsonify(message=ResponseMessage.TOO_MANY_REQUESTS)
                response.status_code = HTTPStatus.TOO_MANY_REQUESTS
                return response
                   
            return func(*args, **kwargs)
        return inner        


bucket = Bucket(Redis(host='auth_bucket', port=config.REDIS_PORT, db=config.REDIS_DB))
