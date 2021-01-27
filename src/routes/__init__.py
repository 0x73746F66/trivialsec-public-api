from flask import jsonify, request, abort, make_response, current_app as app
from flask_login import LoginManager, current_user, logout_user, login_user
from trivialsec.decorators import control_timing_attacks, require_recaptcha
from trivialsec.services.accounts import register
from trivialsec.helpers import messages, hash_password, check_password_policy
from trivialsec.helpers.config import config
from trivialsec.helpers.hmac import validate
from trivialsec.helpers.log_manager import logger
from trivialsec.models.apikey import ApiKey
from trivialsec.models.member import Member
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.invitation import Invitation


@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.before_request
def before_request():
    if request.path in ['/', '/v1', '/healthcheck']:
        return make_response(), 204

    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', f'{config.get_app().get("host_scheme")}{config.get_app().get("host_domain")}')
        response.headers.add("Access-Control-Allow-Headers", "X-ApiKey, X-Date, X-Digest, X-Signature, Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        return response

    apikey = validate(
        raw=request.get_data(as_text=True),
        request_method=request.method,
        uri=request.path,
        headers=request.headers
    )
    if not isinstance(apikey, ApiKey):
        return abort(401)
    # Success - application login and process the request
    member = Member(member_id=apikey.member_id)
    member.hydrate(ttl_seconds=30)
    member.get_roles()
    account = Account(account_id=member.account_id)
    account.hydrate()
    plan = Plan(plan_id=account.plan_id)
    plan.hydrate()
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)
    login_user(member)

    return None

@app.after_request
def after_request(response):
    if request.method in ["GET", "POST"] and hasattr(current_user, 'apikey'):
        response.headers.add('Access-Control-Allow-Origin', f'{config.get_app().get("host_scheme")}{current_user.apikey.allowed_origin}')
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
    plan = Plan(plan_id=account.plan_id)
    plan.hydrate(ttl_seconds=30)
    if not isinstance(plan, Plan):
        logger.debug(f'missing plan for account_id {member.account_id} and user {user_id}')
        return abort(401)
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)

    return member
