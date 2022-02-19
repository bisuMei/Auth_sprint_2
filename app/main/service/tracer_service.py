from jaeger_client import Config
from flask_opentracing import FlaskTracer

from app.main.config import config


tracer = FlaskTracer()


def setup_jaeger(service_name : str = 'movies-api'):
    tracer_config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1,
            },
            'local_agent': {
                'reporting_host': config.JAEGER_HOST,
                'reporting_port': config.JAEGER_PORT,
            }
        },
        service_name=service_name,
        validate=True
    )     
    
    return tracer_config.initialize_tracer()


def init_tracer(app):
    FlaskTracer(setup_jaeger, True, app=app)