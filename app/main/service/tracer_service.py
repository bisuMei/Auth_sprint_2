from jaeger_client import Config
from flask_opentracing import FlaskTracer


tracer = FlaskTracer()


config_ = {
    'sampler': {
        'type': 'const',
        'param': 1,
    }
}


def _setup_jaeger():
    config = Config(
        config=config_,
        service_name='movies-api',
        validate=True,
    )
    return config.initialize_tracer()


def init_tracer(app):
    FlaskTracer(_setup_jaeger, True, app=app)