from jaeger_client import Config
from flask_opentracing import FlaskTracer


tracer = FlaskTracer()


def _setup_jaeger():
    config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1,
            },
            'local_agent': {
                'reporting_host': "jaeger",
                'reporting_port': 6831,
            }
        },
        service_name='movies-api',
        validate=True
    )     
    
    return config.initialize_tracer()


def init_tracer(app):
    FlaskTracer(_setup_jaeger, True, app=app)