from io import BytesIO
from datetime import datetime
from random import random
from base64 import b64encode
from flask import Blueprint, jsonify, request, current_app as app
from flask_login import current_user, login_required
from gunicorn.glogging import logging
import validators
import webauthn
from pyotp import TOTP, random_base32
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_L

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json, require_authz
from trivialsec.helpers import messages, oneway_hash, check_email_rules, is_valid_ipv4_address, is_valid_ipv6_address
from trivialsec.helpers.config import config
from trivialsec.helpers.payments import checkout, create_customer
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.plan import Plan
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa
from trivialsec.models.account import Account
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.invitation import Invitation
from trivialsec.models.role import Role, Roles
from trivialsec.services.accounts import register


logger = logging.getLogger(__name__)
blueprint = Blueprint('account', __name__)

@blueprint.route('/register', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='public_action')
@prepared_json
def api_register(params):
    if not params.get('privacy'):
        params['status'] = 'warning'
        params['message'] = messages.ERR_ACCEPT_EULA
        return jsonify(params)

    if 'email' not in params or not check_email_rules(params.get('email')):
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    try:
        member = register(
            email_addr=params.get('email'),
            company=params.get('company', params.get('email'))
        )
        if not isinstance(member, Member):
            params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
            return jsonify(params)
        else:
            plan = Plan(account_id=member.account_id)
            plan.hydrate('account_id')
            stripe_result = create_customer(member.email)
            plan.stripe_customer_id = stripe_result.get('id')
            plan.persist()
            upsert_contact(recipient_email=params.get('email'), list_name='trials')
            confirmation_url = f"{config.get_app().get('app_url')}{member.confirmation_url}"
            send_email(
                subject="TrivialSec Confirmation",
                recipient=member.email,
                template='registrations',
                data={
                    "activation_url": confirmation_url
                }
            )
            member.confirmation_sent = True
            member.persist()
            params['status'] = 'success'
            params['message'] = messages.OK_REGISTERED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/webauthn-onboarding', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='confirmation_action')
@prepared_json
def api_confirmation_webauthn(params):
    try:
        member = Member()
        member.confirmation_url = f'/confirmation/{params.get("confirmation_hash")}'
        if not member.exists(['confirmation_url']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        member.hydrate()
        mfa = MemberMfa()
        mfa.member_id = member.member_id
        mfa.webauthn_id = params.get("webauthn_id")
        if mfa.exists(['member_id', 'webauthn_id']):
            mfa.hydrate()
        else:
            mfa.type = 'webauthn'
            mfa.created_at = datetime.now()
        mfa.webauthn_challenge = params.get("webauthn_challenge")
        mfa.webauthn_public_key = params.get("webauthn_public_key")
        mfa.active = False
        webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
            rp_id=config.get_app().get("app_domain"),
            origin=config.get_app().get("app_url"),
            registration_response={
                'attObj': params.get('attestationObject'),
                'clientData': params.get('clientDataJSON'),
            },
            challenge=mfa.webauthn_challenge
        )
        webauthn_registration_response.verify()
        mfa.persist()
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED_MFA

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/totp-onboarding', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='confirmation_action')
@prepared_json
def api_registration_totp(params):
    try:
        member = Member()
        member.confirmation_url = f'/confirmation/{params.get("confirmation_hash")}'
        if not member.exists(['confirmation_url']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        member.hydrate()
        totp_code = random_base32()
        totp = TOTP(totp_code)
        mfa = MemberMfa()
        mfa.member_id = member.member_id
        mfa.type = 'totp'
        if mfa.exists(['member_id', 'type']):
            mfa.hydrate(['member_id', 'type'])
        else:
            mfa.created_at = datetime.now()

        mfa.totp_code = totp_code
        mfa.active = False
        mfa.persist()
        provisioning_uri = totp.provisioning_uri(name=member.email, issuer_name='Trivial Security')
        qr_code = QRCode(
            version=5,
            error_correction=ERROR_CORRECT_L,
            box_size=8,
            border=4
        )
        qr_code.add_data(provisioning_uri)
        qr_code.make(fit=True)
        img = qr_code.make_image()
        with BytesIO() as buf:
            img.save(buf, 'png')
            res = buf.getvalue()
            params['qr_code'] = b64encode(res).decode()

        params['totp_code'] = totp_code
        params['status'] = 'success'
        params['message'] = messages.INFO_TOTP_GENERATION

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/update-email', methods=['POST'])
@login_required
@require_authz
@prepared_json
def api_update_email(params):
    try:
        check_member = Member(email=params.get('new_email'))
        if check_member.exists(['email']):
            logger.info('check_member.exists')
            params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
            return jsonify(params)

        if 'new_email' not in params or not check_email_rules(params.get('new_email')):
            logger.info('check_email_rules')
            params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
            return jsonify(params)

        member = Member()
        member.member_id = current_user.member_id
        if not member.exists():
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        member.hydrate()
        from_value = member.email
        member.email = params.get('new_email')
        member.verified = False
        member.confirmation_sent = False
        confirmation_hash = oneway_hash(f'{random()}{member.account_id}')
        member.confirmation_url = f"/verify/{confirmation_hash}"
        member.persist()
        send_email(
            subject="TrivialSec - Email address verification",
            recipient=member.email,
            template='updated_email',
            data={
                "activation_url": f"{config.get_app().get('app_url')}{member.confirmation_url}"
            }
        )
        member.confirmation_sent = True
        member.persist()
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_USER_CHANGE_EMAIL_REQUEST,
            description=f"email updated from {from_value} to {current_user.email}"
        ).persist()
        params['status'] = 'success'
        params['message'] = messages.OK_EMAIL_UPDATE

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/update-billing-email', methods=['POST'])
@login_required
@require_authz
@prepared_json
def api_account_update_billing_email(params):
    try:
        from_value = current_user.account.billing_email
        if not check_email_rules(params.get('billing_email')):
            raise ValueError(f"billing_email {params.get('billing_email')} is not valid")

        current_user.account.billing_email = params.get('billing_email')
        current_user.account.persist()
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_USER_CHANGED_ACCOUNT,
            description=f"billing_email updated from {from_value} to {current_user.account.billing_email}"
        ).persist()
        params['status'] = 'success'
        params['message'] = messages.OK_ACCOUNT_UPDATED
        account_dict = {}
        for col in current_user.account.cols():
            account_dict[col] = getattr(current_user.account, col)
        params['account'] = account_dict

    except Exception as err:
        logger.exception(err)
        params['message'] = messages.ERR_ACCOUNT_UPDATE
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/invitation', methods=['POST'])
@login_required
@prepared_json
def api_invitation(params):
    if 'invite_email' not in params or not check_email_rules(params['invite_email']):
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    try:
        roles = Roles()
        params['role_name'] = None
        for role in roles.load():
            if role.role_id == int(params['invite_role_id']):
                params['role_name'] = role.name

        invitation = Invitation()
        invitation.account_id = current_user.account_id
        invitation.invited_by_member_id = current_user.member_id
        invitation.email = params['invite_email']
        invitation.role_id = params['invite_role_id']
        invitation.message = params.get('invite_message', Invitation.INVITATION_MESSAGE)
        invitation.confirmation_url = f"/confirmation/{oneway_hash(random())}"

        if invitation.exists(['email']) or not invitation.persist():
            params['message'] = messages.ERR_INVITATION_FAILED
            return jsonify(params)

        params['confirmation_url'] = f"{config.get_app().get('app_url')}{invitation.confirmation_url}"
        send_email(
            subject=f"Invitation to join TrivialSec organisation {current_user.account.alias}",
            recipient=invitation.email,
            template='invitations',
            data={
                "invitation_message": invitation.message,
                "activation_url": params['confirmation_url']
            }
        )

        invitation.confirmation_sent = True
        invitation.persist()
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_USER_CREATED_INVITATION,
            description=invitation.email
        ).persist()
        params['status'] = 'success'
        params['message'] = messages.OK_INVITED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)
        params['message'] = messages.ERR_INVITATION_FAILED

    return jsonify(params)

@blueprint.route('/update-configuration', methods=['POST'])
@login_required
def api_update_configuration():
    #TODO use MFA to save account information
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    account_config = AccountConfig(account_id=current_user.account_id)
    account_config.hydrate()
    protected = ['account_id']
    params_keys = set()
    changes = []
    custom_nameservers = False
    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'nameservers':
            custom_nameservers = param.get('value').splitlines()

        if param.get('prop') == 'ignore_list':
            blacklisted_domains = []
            blacklisted_ips = []
            for target in param.get('value').splitlines():
                if is_valid_ipv4_address(target) or is_valid_ipv6_address(target):
                    blacklisted_ips.append(target)
                else:
                    blacklisted_domains.append(target)
            if len(blacklisted_ips) > 0:
                params_keys.add('blacklisted_ips')
                from_val = '' if not isinstance(account_config.blacklisted_ips, str) else '\t'.join(account_config.blacklisted_ips.split('\n'))
                to_val = '\t'.join(blacklisted_ips)
                account_config.blacklisted_ips = '\n'.join(blacklisted_ips)
                changes.append(f"blacklisted_ips from {from_val} to {to_val}")
            if len(blacklisted_domains) > 0:
                params_keys.add('blacklisted_domains')
                from_val = '' if not isinstance(account_config.blacklisted_domains, str) else '\t'.join(account_config.blacklisted_domains.split('\n'))
                to_val = '\t'.join(blacklisted_domains)
                account_config.blacklisted_domains = '\n'.join(blacklisted_domains)
                changes.append(f"blacklisted_domains from {from_val} to {to_val}")
            continue
        params_keys.add(param.get('prop'))
        from_value = getattr(account_config, param.get('prop'))
        setattr(account_config, param.get('prop'), param.get('value'))
        changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")

    if custom_nameservers is not False:
        pass #TODO inform support@trivialsec.com to modify AWS VPC DHCP options

    err = None
    message = messages.OK_ACCOUNT_CONFIG_UPDATED
    if not account_config.persist():
        err = f'Error saving {" ".join(params_keys)}'
        message = messages.ERR_ACCOUNT_UPDATE

    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_USER_CHANGED_ACCOUNT,
        description='\t'.join(changes)
    ).persist()
    account_dict = {}
    for col in account_config.cols():
        account_dict[col] = getattr(account_config, col)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': message,
        'account_config': account_dict,
        'result': err is None
    })

@blueprint.route('/setup', methods=['POST'])
@login_required
def api_setup():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    changes = []
    account_changes = False
    account_config_changes = False
    err = None
    responses = []
    protected = ['verification_hash', 'registered', 'socket_key', 'plan_id', 'account_id']
    params_keys = set()
    account_cols = Account().cols()
    account_config_cols = AccountConfig().cols()
    account_config = AccountConfig(account_id=current_user.account_id)
    account_config.hydrate()

    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'alias' and current_user.account.alias == param.get('value'):
            continue
        if param.get('prop') == 'default_role_id' and \
            int(account_config.default_role_id) > 0 and \
            int(account_config.default_role_id) == int(param.get('value')):
            continue
        if param.get('prop') in account_cols:
            from_value = getattr(current_user.account, param.get('prop'), param.get('value'))
            params_keys.add(param.get('prop'))
            setattr(current_user.account, param.get('prop'), param.get('value'))
            changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")
            account_changes = True
        if param.get('prop') in account_config_cols:
            from_value = getattr(account_config, param.get('prop'), param.get('value'))
            params_keys.add(param.get('prop'))
            setattr(account_config, param.get('prop'), param.get('value'))
            changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")
            account_config_changes = True

    if account_changes and current_user.account.persist() is False:
        err = f'Error saving {" ".join(params_keys)}'
        responses.append(messages.ERR_ACCOUNT_UPDATE)
    if account_config_changes and account_config.persist() is False:
        err = f'Error saving {" ".join(params_keys)} {type(account_config.default_role_id)}'
        responses.append(messages.ERR_ACCOUNT_CONFIG_UPDATE)

    if err is None:
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_USER_CHANGED_ACCOUNT,
            description='\t'.join(changes)
        ).persist()
        responses.append(messages.OK_ACCOUNT_UPDATED)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': "\n".join(responses),
        'result': err is None
    })

@blueprint.route('/checkout', methods=['POST'])
@login_required
def api_checkout():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    plan = Plan(account_id=current_user.account_id)
    plan.hydrate('account_id')
    if params.get('selection') == 'plan_professional_annual':
        price_id = config.stripe['products']['professional'].get('yearly')
    elif params.get('selection') == 'plan_professional_monthly':
        price_id = config.stripe['products']['professional'].get('monthly')
    elif params.get('selection') == 'plan_standard_annual':
        price_id = config.stripe['products']['standard'].get('yearly')
    elif params.get('selection') == 'plan_standard_monthly':
        price_id = config.stripe['products']['standard'].get('monthly')
    elif params.get('selection') == 'plan_enterprise':
        return jsonify({
            'status': 'info',
            'message': 'Please contact us to activate your Enterprise plan',
            'result': None
        })
    else:
        return jsonify({
            'status': 'error',
            'error': f"invalid selection {params.get('selection')}",
            'message': messages.ERR_SUBSCRIPTION,
            'result': None
        })

    stripe_result = checkout(
        price_id=price_id,
        customer_id=plan.stripe_customer_id
    )
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_USER_CHANGED_ACCOUNT,
        description='Started subscription checkout session'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_CHECKOUT_SESSION,
        'result': stripe_result
    })

@blueprint.route('/update-member', methods=['POST'])
@login_required
def api_update_member():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    err = None
    responses = []
    member_dict = {}
    member = Member(
        member_id=params.get('member_id'),
        account_id=current_user.account_id
    )
    if not member.hydrate(['member_id', 'account_id']):
        err = messages.ERR_ORG_MEMBER
    if member.email != params.get('email', member.email):
        prior_email = member.email
        member.email = params.get('email')
        member.verified = False
        member.confirmation_sent = False
        member.confirmation_url = f"/confirmation/{oneway_hash(random())}"
        member.persist()
        confirmation_url = f"{config.get_app().get('app_url')}{member.confirmation_url}"
        try:
            send_email(
                subject="TrivialSec - email address updated",
                recipient=params.get('email'),
                template='updated_email',
                data={
                    "activation_url": confirmation_url
                }
            )
            member.confirmation_sent = True
            if member.persist():
                responses.append(messages.OK_EMAIL_UPDATE)
                ActivityLog(
                    member_id=current_user.member_id,
                    action=ActivityLog.ACTION_USER_CHANGED_MEMBER,
                    description=f'changed {prior_email} to {member.email}'
                ).persist()

        except Exception as ex:
            logger.exception(ex)
            err = str(ex)
            responses.append(messages.ERR_EMAIL_NOT_SENT)

    new_roles = []
    current_roles = []
    member.get_roles()
    roles_changed = False
    for role_id in params.get('roles'):
        new_roles.append(int(role_id))
    for role in member.roles:
        if int(role.role_id) not in new_roles:
            member.remove_role(role)
            roles_changed = True
            ActivityLog(
                member_id=current_user.member_id,
                action=ActivityLog.ACTION_USER_CHANGED_MEMBER,
                description=f'removed role {role.name} from {member.email}'
            ).persist()
        else:
            current_roles.append(int(role.role_id))

    for role_id in new_roles:
        if role_id not in current_roles:
            new_role = Role(role_id=role_id)
            new_role.hydrate()
            member.add_role(new_role)
            ActivityLog(
                member_id=current_user.member_id,
                action=ActivityLog.ACTION_USER_CHANGED_MEMBER,
                description=f'granted role {new_role.name} to {member.email}'
            ).persist()
            roles_changed = True

    if roles_changed is True:
        responses.append(messages.OK_ACCOUNT_UPDATED)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': '\n'.join(responses),
        'result': member_dict
    })
