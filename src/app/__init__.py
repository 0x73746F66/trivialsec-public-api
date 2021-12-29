from os import getenv
from flask import Flask
from flask_session import Session
from werkzeug.debug import DebuggedApplication
from werkzeug.middleware.proxy_fix import ProxyFix
from trivialsec.helpers.config import config


def create_app():
    app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)
    app.config.update(
        PREFERRED_URL_SCHEME='https',
        SECRET_KEY=config.session_secret_key,
        SESSION_TYPE='redis',
        SESSION_USE_SIGNER=False,
        SESSION_REDIS=config.redis_client
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
        from routes.recovery import blueprint as recovery_blueprint
        from routes.auth import blueprint as auth_blueprint
        from routes.account import blueprint as account_blueprint
        from routes.project import blueprint as project_blueprint
        from routes.domain import blueprint as domain_blueprint
        app.register_blueprint(api_blueprint, url_prefix='/v1')
        app.register_blueprint(recovery_blueprint, url_prefix='/v1/recovery')
        app.register_blueprint(auth_blueprint, url_prefix='/v1/auth')
        app.register_blueprint(account_blueprint, url_prefix='/v1/account')
        app.register_blueprint(project_blueprint, url_prefix='/v1/project')
        app.register_blueprint(domain_blueprint, url_prefix='/v1/domain')

    return app
