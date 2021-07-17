from flask import request, abort, Response, make_response, g, current_app as app
from flask_login import LoginManager, login_user, logout_user
from gunicorn.glogging import logging
from trivialsec.helpers import config, mohawk_receiver, Receiver
from trivialsec.models.apikey import ApiKey
from trivialsec.models.member import Member
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.services.apikey import get_valid_key

__version__ = 'v1'


logger = logging.getLogger(__name__)

@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.before_request
def before_request():
    no_content = [
        '/',
        f'/{__version__}',
        '/healthcheck'
    ]
    if request.path in no_content:
        return make_response(), 204

    if request.method in ["OPTIONS"]:
        response = make_response()
        response.headers.add("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        allowed_origin = config.get_app().get("site_url")
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("app_url"):
            allowed_origin = config.get_app().get("app_url")
        elif request.environ.get('HTTP_ORIGIN') == config.get_app().get("site_url"):
            allowed_origin = config.get_app().get("site_url")
        response.headers.add('Access-Control-Allow-Origin', allowed_origin)
        return response, 204

    res_401 = Response('{"status": 401, "message": "Unauthorized"}', 401, {'Content-Type': 'application/json'})
    authorization_header = request.headers.get('Authorization')
    if authorization_header is not None:
        g.receiver = mohawk_receiver(request) # pylint: disable=assigning-non-slot
        if not isinstance(g.receiver, Receiver):
            logger.error(f'hawk validate failed {authorization_header}')
            return res_401

        # Success - application login and process the request
        apikey :ApiKey = get_valid_key(g.receiver.parsed_header.get('id'))
        if apikey is None or not isinstance(apikey, ApiKey):
            logger.error('no apikey')
            return res_401

        g.apikey = apikey # pylint: disable=assigning-non-slot
        member = Member(member_id=apikey.member_id)
        member.hydrate(ttl_seconds=30)
        member.get_roles()
        account = Account(account_id=member.account_id)
        account.hydrate()
        plan = Plan(account_id=account.account_id)
        plan.hydrate('account_id')
        setattr(account, 'plan', plan)
        setattr(member, 'account', account)
        setattr(member, 'apikey', apikey)
        login_user(member)

    return None

@app.after_request
def after_request(response):
    if response.status_code == 204:
        return response
    if response.status_code == 401:
        response.headers.add('WWW-Authenticate', 'Hawk realm="Login Required"')

    try:
        logout_user()
    except Exception:
        pass

    if hasattr(g, 'receiver') and isinstance(g.receiver, Receiver):
        response.headers.add('Server-Authorization', g.receiver.respond(content=response.get_data(as_text=True), content_type=response.content_type))

    if request.method in ["GET", "POST"]:
        allowed_origin_assets = config.get_app().get("asset_url")
        allowed_origin_api = config.get_app().get("api_url")
        allowed_origin_site = config.get_app().get("site_url")
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("app_url"):
            allowed_origin_site = config.get_app().get("app_url")
        elif request.environ.get('HTTP_ORIGIN') == config.get_app().get("site_url"):
            allowed_origin_site = config.get_app().get("site_url")
        if hasattr(g, 'apikey') and isinstance(g.apikey, ApiKey):
            allowed_origin_site = g.apikey.allowed_origin
        response.headers.add('Access-Control-Allow-Origin', allowed_origin_site)
        if request.method == "GET":
            response.headers.add('Content-Security-Policy', '; '.join([
                f"default-src 'self' {allowed_origin_assets}",
                "frame-src https://www.google.com https://recaptcha.google.com",
                "form-action 'none'",
                "frame-ancestors 'none'",
                f"connect-src {allowed_origin_api}",
                f"script-src https://www.gstatic.com https://www.google.com {allowed_origin_assets}",
                f"font-src https://fonts.gstatic.com {allowed_origin_assets} {allowed_origin_site}",
                f"style-src https://fonts.googleapis.com {allowed_origin_assets} {allowed_origin_site}"
            ]))

    return response

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id: int) -> Member:
    member = Member(member_id=user_id)
    member.hydrate(ttl_seconds=30)
    if not isinstance(member, Member):
        return abort(401)
    member.get_roles()
    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    apikey.hydrate(['member_id', 'comment'], ttl_seconds=10)
    if apikey.api_key_secret is None or apikey.active is not True:
        logger.debug(f'api_key_secret empty or inactive public-api key for user {user_id}')
        return abort(401)
    account = Account(account_id=member.account_id)
    account.hydrate(ttl_seconds=30)
    if not isinstance(account, Account):
        logger.debug(f'missing account_id {member.account_id} for user {user_id}')
        return abort(401)
    plan = Plan(account_id=account.account_id)
    plan.hydrate('account_id', ttl_seconds=30)
    if not isinstance(plan, Plan):
        logger.debug(f'missing plan for account_id {member.account_id} and user {user_id}')
        return abort(401)
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)

    return member
