from datetime import datetime
from flask import request, abort, Response, make_response, g, current_app as app
from flask_login import LoginManager, login_user, logout_user
from gunicorn.glogging import logging
from trivialsec.helpers.config import config
from trivialsec.helpers.hmac import HMAC
from trivialsec.models.apikey import ApiKey
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa, MemberMfas
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.services.apikey import get_valid_key


logger = logging.getLogger(__name__)

@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.before_request
def before_request():
    no_content = [
        '/',
        '/v1',
        '/healthcheck'
    ]
    if request.path in no_content:
        return make_response(), 204

    if request.method in ["OPTIONS"]:
        response = make_response()
        response.headers.add("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Authorization-Token")
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
        authz = HMAC(request)
        # Success - application login and process the request
        apikey :ApiKey = get_valid_key(authz.parsed_header.get('id'))
        if apikey is None or not isinstance(apikey, ApiKey):
            logger.error('no apikey')
            return res_401

        if not authz.validate(apikey.api_key_secret):
            logger.error(f'server_mac {authz.server_mac}')
            return res_401

        member = load_user(apikey.member_id)
        login_user(member)

    return None

@app.after_request
def after_request(response):
    if response.status_code == 204:
        return response
    if response.status_code == 401:
        response.headers.add('WWW-Authenticate', 'HMAC realm="Login Required"')

    try:
        logout_user()
    except Exception:
        pass

    # response.headers.add('Server-Authorization', HMAC(content=response.get_data(as_text=True)))
    if request.method in ["GET", "POST"]:
        allowed_origin_assets = config.get_app().get("asset_url")
        allowed_origin_api = config.get_app().get("api_url")
        allowed_origin_site = config.get_app().get("site_url")
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("app_url"):
            allowed_origin_site = config.get_app().get("app_url")
        elif request.environ.get('HTTP_ORIGIN') == config.get_app().get("site_url"):
            allowed_origin_site = config.get_app().get("site_url")
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

    totp_mfa = MemberMfa()
    totp_mfa.member_id = member.member_id
    totp_mfa.type = 'totp'
    totp_mfa.active = True
    if totp_mfa.exists(['member_id', 'type', 'active']):
        totp_mfa.hydrate()
        setattr(member, 'totp_mfa_id', totp_mfa.mfa_id)

    u2f_keys = []
    index = 0
    for u2f_key in MemberMfas().find_by([('member_id', member.member_id), ('type', 'webauthn'), ('active', True)], limit=1000):
        index += 1

        u2f_keys.append({
            'mfa_id': u2f_key.mfa_id,
            'name': u2f_key.name or f'Key {index}',
            'webauthn_id': u2f_key.webauthn_id,
            'registered': u2f_key.created_at if not isinstance(u2f_key.created_at, datetime) else u2f_key.created_at.isoformat()
        })

    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)
    setattr(member, 'u2f_keys', u2f_keys)

    return member
