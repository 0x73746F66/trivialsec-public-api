from io import BytesIO
from datetime import datetime
from random import random
from base64 import b64encode
from flask import Blueprint, jsonify, request, current_app as app
from flask_login import current_user, login_required
from gunicorn.glogging import logging
import webauthn
from pyotp import TOTP, random_base32
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_L

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json
from trivialsec.helpers import messages, oneway_hash, check_email_rules
from trivialsec.helpers.config import config
from trivialsec.helpers.authz import get_authorization_token, start_transaction, is_active_transaction
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa
from trivialsec.models.account import Account


logger = logging.getLogger(__name__)
blueprint = Blueprint('auth', __name__)

@blueprint.route('/setup/verify-webauthn', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='authorization_action')
@prepared_json
def api_setup_verify_webauthn(params):
    try:
        member = Member()
        member.confirmation_url = f'/confirmation/{params.get("confirmation_hash")}'
        if not member.exists(['confirmation_url']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        member.hydrate()
        mfa = MemberMfa()
        mfa.member_id = member.member_id
        mfa.webauthn_id = params['assertion_response'].get('rawId')
        mfa.exists(['member_id', 'webauthn_id'])
        if not mfa.hydrate():
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        webauthn_user = webauthn.WebAuthnUser(
            user_id=member.email.encode('utf8'),
            username=member.email,
            display_name=member.email,
            icon_url=None,
            sign_count=0,
            credential_id=str(webauthn.webauthn._webauthn_b64_decode(mfa.webauthn_id)),
            public_key=mfa.webauthn_public_key,
            rp_id=config.get_app().get("app_domain")
        )
        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            assertion_response=params['assertion_response'],
            challenge=mfa.webauthn_challenge,
            origin=config.get_app().get("app_url"),
            uv_required=False
        )
        webauthn_assertion_response.verify()

        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr

        scratch = oneway_hash(f'{random()}{member.member_id}')
        member.scratch_code = f'{scratch[:4]}-{scratch[4:10]}-{scratch[10:18]}-{scratch[18:24]}'.upper()
        member.confirmation_url = f"/login/{oneway_hash(f'{random()}{remote_addr}')}"
        member.verified = True
        member.persist()
        magic_link = f"{config.get_app().get('app_url')}{member.confirmation_url}"
        upsert_contact(recipient_email=member.email, list_name='members')
        send_email(
            subject="TrivialSec Magic Link",
            recipient=member.email,
            template='magic_link',
            data={
                "magic_link": magic_link
            }
        )
        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_LOGIN,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
        mfa.active = True
        mfa.persist()
        params['status']        = 'success'
        params['device_id']     = mfa.mfa_id
        params['scratch_code']  = member.scratch_code
        params['message']       = messages.OK_REGISTERED_MFA
        params['description']   = messages.OK_MAGIC_LINK_SENT

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/setup/verify-totp', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='authorization_action')
@prepared_json
def api_setup_verify_totp(params):
    try:
        member = Member()
        member.confirmation_url = f'/confirmation/{params.get("confirmation_hash")}'
        if not member.exists(['confirmation_url']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        member.hydrate()
        mfa = MemberMfa()
        mfa.member_id = member.member_id
        mfa.type = 'totp'
        if not mfa.hydrate(['member_id', 'type']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        totp = TOTP(mfa.totp_code)
        if not totp.verify(int(params.get("totp_code"))):
            params['message'] = messages.ERR_VALIDATION_TOTP
            return jsonify(params)

        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr

        scratch = oneway_hash(f'{random()}{member.member_id}')
        member.scratch_code = f'{scratch[:4]}-{scratch[4:10]}-{scratch[10:18]}-{scratch[18:24]}'.upper()
        member.confirmation_url = f"/login/{oneway_hash(f'{random()}{remote_addr}')}"
        member.verified = True
        member.persist()
        magic_link = f"{config.get_app().get('app_url')}{member.confirmation_url}"
        upsert_contact(recipient_email=member.email, list_name='members')
        send_email(
            subject="TrivialSec Magic Link",
            recipient=member.email,
            template='magic_link',
            data={
                "magic_link": magic_link
            }
        )
        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_LOGIN,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
        mfa.active = True
        mfa.persist()
        params['status']        = 'success'
        params['scratch_code']  = member.scratch_code
        params['message']       = messages.OK_REGISTERED_MFA
        params['description']   = messages.OK_MAGIC_LINK_SENT

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/setup/webauthn-device-name', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='name_device_action')
@prepared_json
def api_setup_webauthn_device_name(params):
    try:
        mfa = MemberMfa()
        mfa.mfa_id = params.get("device_id")
        mfa.hydrate()
        if not mfa.member_id:
            return jsonify(params)

        mfa.name = params.get("device_name")
        if not mfa.name:
            return jsonify(params)

        mfa.persist()
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED_MFA

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/rename-mfa-device', methods=['POST'])
@login_required
@prepared_json
def api_rename_mfa_device(params):
    try:
        mfa = MemberMfa()
        mfa.mfa_id = params.get("device_id")
        mfa.hydrate()
        if not mfa.member_id:
            return jsonify(params)

        mfa.name = params.get("device_name")
        if not mfa.name:
            return jsonify(params)

        mfa.persist()
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED_MFA

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/remove-mfa-device', methods=['POST'])
@login_required
@prepared_json
def api_mfa_remove_device(params):
    try:
        if len(current_user.u2f_keys) == 1 and not hasattr(current_user, 'totp_mfa_id'):
            params['message'] = messages.ERR_MFA_REMOVE_LAST_KEY
            return jsonify(params)
        if len(current_user.u2f_keys) < 2 and not hasattr(current_user, 'totp_mfa_id'):
            params['message'] = messages.OK_GENERIC
            return jsonify(params)

        mfa = MemberMfa()
        mfa.mfa_id = params.get("device_id")
        mfa.hydrate()
        if not mfa.member_id:
            return jsonify(params)

        if mfa.delete():
            params['status'] = 'success'
            params['message'] = messages.OK_MFA_REMOVED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/magic-link', methods=['POST'])
@require_recaptcha(action='public_action')
@prepared_json
def api_magic_link(params):
    email_addr = params.get('email')
    member = Member(email=email_addr)
    member.hydrate('email')
    if member.member_id is None:
        logger.debug(f'No user for {email_addr}')
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if not member.verified:
        logger.debug(f'unverified user {member.member_id}')
        params['message'] = messages.ERR_MEMBER_VERIFICATION
        return jsonify(params)

    res = check_email_rules(email_addr)
    if not res:
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    account = Account(account_id=member.account_id)
    if not account.hydrate():
        logger.debug(f'unverified user {member.member_id}')
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr

    member.confirmation_url = f"/login/{oneway_hash(f'{random()}{remote_addr}')}"
    member.persist()
    magic_link = f"{config.get_app().get('app_url')}{member.confirmation_url}"
    send_email(
        subject="TrivialSec Magic Link",
        recipient=member.email,
        template='magic_link',
        data={
            "magic_link": magic_link
        }
    )
    ActivityLog(
        member_id=member.member_id,
        action=ActivityLog.ACTION_USER_LOGIN,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    params['status'] = 'success'
    params['message'] = messages.OK_MAGIC_LINK_SENT

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/authorization-verify', methods=['POST'])
@login_required
@prepared_json
def api_authorization_verify(params):
    try:
        transaction_id = params.get('transaction_id')
        if transaction_id is None:
            params['message'] = messages.ERR_AUTHORIZATION
            raise ValueError('missing transaction_id')

        mfa = MemberMfa()
        mfa.member_id = current_user.member_id
        if 'assertion_response' in params:
            mfa.webauthn_id = params['assertion_response'].get('rawId')
            mfa.exists(['member_id', 'webauthn_id'])
            if not mfa.hydrate():
                params['message'] = messages.ERR_AUTHORIZATION
                raise ValueError('transaction ids do not match')

            webauthn_user = webauthn.WebAuthnUser(
                user_id=current_user.email.encode('utf8'),
                username=current_user.email,
                display_name=current_user.email,
                icon_url=None,
                sign_count=0,
                credential_id=str(webauthn.webauthn._webauthn_b64_decode(mfa.webauthn_id)), # pylint: disable=protected-access
                public_key=mfa.webauthn_public_key,
                rp_id=config.get_app().get("app_domain")
            )
            webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
                webauthn_user,
                assertion_response=params['assertion_response'],
                challenge=mfa.webauthn_challenge,
                origin=config.get_app().get("app_url"),
                uv_required=False
            )
            webauthn_assertion_response.verify()
            params['authorization_token'] = get_authorization_token(mfa.webauthn_id, transaction_id)

        elif 'totp_code' in params:
            mfa.type = 'totp'
            if mfa.exists(['member_id', 'type']):
                mfa.hydrate(['member_id', 'type'])
            else:
                raise ValueError('TOTP is not available')

            totp = TOTP(mfa.totp_code)
            if not mfa.mfa_id:
                params['message'] = messages.ERR_ORG_MEMBER
                raise ValueError('missing mfa_id')

            if not totp.verify(int(params.get("totp_code"))):
                params['message'] = messages.ERR_AUTHORIZATION
                raise ValueError('TOTP verification failed')
            params['authorization_token'] = get_authorization_token(mfa.totp_code, transaction_id)
        else:
            params['message'] = messages.ERR_AUTHORIZATION
            raise ValueError('no authz method provided')

        params['status']              = 'success'
        params['message']             = messages.OK_AUTHENTICATED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/authorization-check', methods=['POST'])
@login_required
@prepared_json
def api_authorization_check(params):
    try:
        if params['target'] in config.public_endpoints:
            params['status'] = 'success'
            params['message'] = messages.OK_GENERIC
            return jsonify(params)

        authorisation_required = False
        for check_path in config.require_authz:
            if params['target'].startswith(check_path):
                authorisation_required = True
                break

        if authorisation_required is False:
            params['status'] = 'success'
            params['message'] = messages.OK_GENERIC
            return jsonify(params)

        if not is_active_transaction(params['transaction_id'], params['target']):
            params['transaction_id'] = start_transaction(params['target'])
            params['status'] = 'info'
            params['message'] = messages.INFO_AUTHORISATION_REQUIRED
            return jsonify(params)

        cache_key = f'{config.app_version}{params["authorization_token"]}'
        stored_value = config.redis_client.get(cache_key)
        if stored_value is None:
            params['status'] = 'info'
            params['message'] = messages.INFO_AUTHORISATION_REQUIRED
        else:
            params['status'] = 'success'
            params['message'] = messages.OK_GENERIC

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/transaction', methods=['POST'])
@login_required
@prepared_json
def api_transaction(params):
    try:
        if params['target'] in config.public_endpoints:
            return jsonify(params)

        for check_path in config.require_authz:
            if params['target'].startswith(check_path):
                params['transaction_id'] = start_transaction(params['target'])
                params['message'] = messages.INFO_AUTHORISATION_REQUIRED
                break

        params['status'] = 'success'
        if params['message'] != messages.INFO_AUTHORISATION_REQUIRED:
            params['message'] = messages.OK_GENERIC

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/add-webauthn', methods=['POST'])
@login_required
@prepared_json
def api_add_webauthn(params):
    try:
        if params.get('assertion_response') is not None:
            mfa = MemberMfa()
            mfa.member_id = current_user.member_id
            mfa.webauthn_id = params['assertion_response'].get('rawId')
            mfa.exists(['member_id', 'webauthn_id'])
            if not mfa.hydrate():
                params['message'] = messages.ERR_ORG_MEMBER
                return jsonify(params)

            webauthn_user = webauthn.WebAuthnUser(
                user_id=current_user.email.encode('utf8'),
                username=current_user.email,
                display_name=current_user.email,
                icon_url=None,
                sign_count=0,
                credential_id=str(webauthn.webauthn._webauthn_b64_decode(mfa.webauthn_id)),
                public_key=mfa.webauthn_public_key,
                rp_id=config.get_app().get("app_domain")
            )
            webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
                webauthn_user,
                assertion_response=params['assertion_response'],
                challenge=mfa.webauthn_challenge,
                origin=config.get_app().get("app_url"),
                uv_required=False
            )
            webauthn_assertion_response.verify()
            mfa.active = True
            mfa.persist()
            ActivityLog(
                member_id=current_user.member_id,
                action=ActivityLog.ACTION_ADD_MFA_U2F,
                description=mfa.mfa_id
            ).persist()
            params['status']        = 'success'
            params['message']       = messages.OK_REGISTERED_MFA
        else:
            mfa = MemberMfa()
            mfa.member_id = current_user.member_id
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

@blueprint.route('/add-totp', methods=['GET', 'POST'])
@login_required
@prepared_json
def api_add_totp(params):
    try:
        mfa = MemberMfa()
        mfa.type = 'totp'
        mfa.member_id = current_user.member_id
        if mfa.exists(['member_id', 'type']):
            mfa.hydrate(['member_id', 'type'])
        else:
            mfa.totp_code = random_base32()
            mfa.created_at = datetime.now()

        totp = TOTP(mfa.totp_code)
        if request.method == 'GET':
            mfa.member_id = current_user.member_id
            if mfa.exists(['member_id', 'type']):
                mfa.hydrate(['member_id', 'type'])
            else:
                mfa.created_at = datetime.now()

            mfa.active = False
            mfa.persist()
            provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name='Trivial Security')
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

            params['totp_code'] = mfa.totp_code
            params['status'] = 'success'
            params['message'] = messages.INFO_TOTP_GENERATION

        if request.method == 'POST':
            if not mfa.mfa_id:
                params['message'] = messages.ERR_ORG_MEMBER
                return jsonify(params)

            if not totp.verify(int(params.get("totp_code"))):
                params['message'] = messages.ERR_VALIDATION_TOTP
                return jsonify(params)

            mfa.active = True
            mfa.persist()
            ActivityLog(
                member_id=current_user.member_id,
                action=ActivityLog.ACTION_ADD_MFA_TOTP,
                description=mfa.mfa_id
            ).persist()
            params['status']        = 'success'
            params['message']       = messages.OK_REGISTERED_MFA

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)
