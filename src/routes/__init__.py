from flask import jsonify, request, abort, make_response, current_app as app
from flask_login import LoginManager, current_user, logout_user, login_user
from trivialsec.decorators import control_timing_attacks, require_recaptcha
from trivialsec.services.accounts import register
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.helpers import messages, hash_password, oneway_hash, check_password_policy, check_email_rules
from trivialsec.helpers.config import config
from trivialsec.helpers.hmac import validate
from trivialsec.helpers.log_manager import logger
from trivialsec.models import ApiKey, Member, Account, Plan, ActivityLog, Invitation, Subscriber


@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.before_request
def before_request():
    if request.path == '/':
        #TODO API Documentation
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
    apikey.hydrate(['member_id', 'comment'])
    if apikey.api_key_secret is None or apikey.active is not True:
        return abort(401)
    account = Account(account_id=member.account_id)
    account.hydrate()
    if not isinstance(account, Account):
        return abort(401)
    plan = Plan(plan_id=account.plan_id)
    plan.hydrate()
    if not isinstance(plan, Plan):
        return abort(401)
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)

    return member

@control_timing_attacks(seconds=2)
@app.route('/confirm-password', methods=['POST'])
@require_recaptcha(action='invitation_action')
def api_invitation_confirm_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    invitee = Invitation()
    invitee.confirmation_url = params['confirmation_url']
    if invitee.exists(['confirmation_url']):
        invitee.hydrate()
    else:
        return abort(403)

    if 'password1' not in params or 'password2' not in params:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password1'] != params['password2']:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = check_password_policy(params['password1'])
    if not res:
        errors.append(messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        member = register(
            account_id=invitee.account_id,
            role_id=invitee.role_id,
            email_addr=invitee.email,
            passwd=params.get('password1'),
            verified=True,
            selected_plan={
                'name': 'Pending',
                'cost': '0.00',
                'currency': 'AUD',
                'active_daily': 0,
                'scheduled_active_daily': 0,
                'passive_daily': 0,
                'scheduled_passive_daily': 0,
                'git_integration_daily': 0,
                'source_code_daily': 0,
                'dependency_support_rating': 0,
                'alert_email': False,
                'alert_integrations': False,
                'threatintel': False,
                'compromise_indicators': False,
                'typosquatting': False
            }
        )
        if not isinstance(member, Member):
            errors.append(messages.ERR_ACCOUNT_UPDATE)

        invitee.member_id = member.member_id
        invitee.persist()
        login_user(member)
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr
        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_LOGIN,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()

    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
    else:
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED

    del params['password1']
    del params['password2']

    return jsonify(params)

@control_timing_attacks(seconds=2)
@app.route('/change-password', methods=['POST'])
@require_recaptcha(action='password_reset_action')
def api_change_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    check_member = Member()
    check_member.confirmation_url = params['confirmation_url']
    if check_member.exists(['confirmation_url']):
        check_member.hydrate()
    else:
        return abort(403)

    if 'password1' not in params or 'password2' not in params:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password1'] != params['password2']:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = check_password_policy(params['password1'])
    if not res:
        errors.append(messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        check_member.password = hash_password(params['password1'])
        check_member.verified = True
        res = check_member.persist()
        if not res:
            errors.append(messages.ERR_ACCOUNT_UPDATE)
            params['status'] = 'error'
            params['message'] = "\n".join(errors)
            return jsonify(params)

        login_user(check_member)
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr
        ActivityLog(
            member_id=check_member.member_id,
            action=ActivityLog.ACTION_USER_CHANGED_PASSWORD,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
    else:
        params['status'] = 'success'
        params['message'] = messages.OK_PASSWORD_RESET

    del params['password1']
    del params['password2']

    return jsonify(params)

@control_timing_attacks(seconds=2)
@app.route('/password-reset', methods=['POST'])
@require_recaptcha(action='login_action')
def api_password_reset():
    params = request.get_json()
    res = check_email_rules(params.get('email'))
    if res is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    check_member = Member(email=params.get('email'))
    check_member.hydrate('email')
    if check_member.exists(['email']) is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    check_member.verified = False
    check_member.confirmation_sent = False
    check_member.confirmation_url = f"/password-reset/{oneway_hash(params.get('email'))}"
    check_member.persist()

    confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{check_member.confirmation_url}"
    send_email(
        subject="TrivialSec - password reset request",
        recipient=check_member.email,
        template='reset_password',
        data={
            "activation_url": confirmation_url
        }
    )
    check_member.confirmation_sent = True
    res = check_member.persist()
    if res is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_USER_RESET_PASSWORD_REQUEST,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    params['status'] = 'info'
    params['message'] = messages.OK_PASSWORD_RESET_SENT

    return jsonify(params)

@control_timing_attacks(seconds=2)
@app.route('/subscribe', methods=['POST'])
@require_recaptcha(action='subscribe_action')
def api_subscribe():
    exists, saved = (False, False)
    error = None
    params = request.get_json()
    del params['recaptcha_token']

    if 'email' not in params or not check_email_rules(params.get('email')):
        error = messages.ERR_VALIDATION_EMAIL_RULES

    if error is not None:
        params['status'] = 'error'
        params['message'] = error
        return jsonify(params)

    try:
        subscriber = Subscriber()
        subscriber.email = params['email']
        exists = subscriber.exists(['email'])
        if exists:
            old_subscriber = Subscriber(subscriber_id=subscriber.subscriber_id)
            old_subscriber.hydrate()
            subscriber.created_at = old_subscriber.created_at
        upsert_contact(recipient_email=subscriber.email)
        saved = subscriber.persist()
        if saved:
            send_email(
                subject="Subscribed to TrivialSec updates",
                recipient=subscriber.email,
                template='subscriptions',
                group='subscriptions',
                data=dict()
            )

    except Exception as err:
        logger.exception(err)
        params['status'] = 'error'
        params['error'] = str(err)
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES

    if exists or saved:
        params['status'] = 'success'
        params['message'] = messages.OK_SUBSCRIBED

    return jsonify(params)
