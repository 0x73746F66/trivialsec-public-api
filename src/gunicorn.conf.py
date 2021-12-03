from os import getenv
import multiprocessing
from dotenv import dotenv_values

env_vars = dotenv_values(".env")
num_cpu :int = multiprocessing.cpu_count()
wsgi_app :str = 'app:create_app()'
proc_name :str = getenv('APP_NAME', env_vars.get('APP_NAME', 'trivialsec'))
loglevel :str = getenv('LOG_LEVEL', env_vars.get('LOG_LEVEL', 'ERROR'))
logconfig_dict = {
    'version': 1,
    'formatters': {
        'default_formatter': {
            'class': 'logging.Formatter',
            'format': '[%(asctime)s] %(levelname)-8s [%(name)s:%(lineno)s] %(module)s %(process)-4d %(thread)d %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': loglevel,
            'formatter': 'default_formatter',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': loglevel,
            'maxBytes': 1024*1024,
            'backupCount': 5,
            'filename': '/var/log/gunicorn/application.log',
            'formatter': 'default_formatter'
        },
    },
    'loggers': {
        'logs': {
            'handlers': ['file', 'console'],
            'level': loglevel,
            'propagate': True,
        }
    },
    'root': {
        'level': loglevel,
        'propagate': True,
        'handlers': ['file', 'console']
    },
    'incremental': False,
    'disable_existing_loggers': False,
}
user :str = 'trivialsec'
group :str = 'trivialsec'
chdir :str = '/srv/app'
pythonpath :str = '/srv/app'
strip_header_spaces :bool = True
accesslog :str = '/var/log/gunicorn/access.log'
disable_redirect_access_to_syslog :bool = True
errorlog :str = '/var/log/gunicorn/error.log'
bind :str = f"0.0.0.0:{getenv('FLASK_RUN_PORT', env_vars.get('FLASK_RUN_PORT', '5081'))}"
workers :int = num_cpu * 2 + 1
threads :int = num_cpu * 2
timeout :int = 20
graceful_timeout :int = 30
keepalive :int = 2
limit_request_line :int = 4094
limit_request_field_size :int = 8190
reload :bool = getenv('FLASK_DEBUG', env_vars.get('FLASK_DEBUG', '0')) == '1'
reload_engine :str = 'poll'
preload_app :bool = True

# def on_starting(server):
#     print('starting gunicorn')

# def on_reload(server):
#     print('reload gunicorn')

# def when_ready(server):
#     print('ready gunicorn')

# def pre_fork(server, worker):
#     print('pre_fork gunicorn')

# def post_fork(server, worker):
#     print('post_fork gunicorn')

# def worker_int(worker):
#     print('worker_int gunicorn')

# def post_worker_init(worker):
#     print('post_worker_init gunicorn')

# def worker_abort(worker):
#     print('worker_abort gunicorn')

# def pre_exec(server):
#     print('pre_exec gunicorn')

# def pre_request(worker, req):
#     worker.log.info(f"{req.method} {req.path}")

# def post_request(worker, req, environ, resp):
#     print('post_request gunicorn')

# def child_exit(server, worker):
#     print('child_exit gunicorn')

# def worker_exit(server, worker):
#     print('worker_exit gunicorn')

# def on_exit(server):
#     print('on_exit gunicorn')
