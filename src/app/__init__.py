from os import environ
import redis
from flask import Flask
from flask_sessionstore import Session
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config

logger.configure(log_level=config.log_level)
logger.create_stream_logger()
logger.create_file_logger(file_path=config.log_file)
app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)

if 'FLASK_DEBUG' in environ:
    app.debug = True
    from werkzeug.debug import DebuggedApplication
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

app.config['SECRET_KEY'] = config.session_secret_key
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis.Redis(host=config.redis.get('host'), ssl=bool(config.redis.get('ssl')))
Session(app)
with app.app_context():
    from routes.api import blueprint as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/v1')
