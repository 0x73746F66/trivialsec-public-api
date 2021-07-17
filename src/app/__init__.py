from os import getenv
import redis
from flask import Flask
from flask_sessionstore import Session
from werkzeug.debug import DebuggedApplication
from werkzeug.middleware.proxy_fix import ProxyFix
from trivialsec.helpers.config import config

def create_app():
    app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)
    app.config.update(
        PREFERRED_URL_SCHEME='https',
        SECRET_KEY=config.session_secret_key,
        SESSION_TYPE='redis',
        SESSION_USE_SIGNER=True,
        SESSION_REDIS=redis.Redis(host=config.redis.get('host'), ssl=bool(config.redis.get('ssl')))
    )

    if getenv('FLASK_DEBUG') == '1':
        app.config.update(
            DEBUG=True,
            PREFERRED_URL_SCHEME='https'
        )
        app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
    Session(app)
    with app.app_context():
        from routes.api import blueprint as api_blueprint
        app.register_blueprint(api_blueprint, url_prefix='/v1')

    return app
