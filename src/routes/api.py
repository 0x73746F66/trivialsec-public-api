from io import BytesIO
from datetime import datetime
from random import random
from base64 import b64encode
from flask import Blueprint, jsonify, request, abort, current_app as app
from flask_login import current_user, login_required
from gunicorn.glogging import logging
import webauthn
from pyotp import TOTP, random_base32
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_L

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json
from trivialsec.helpers import messages, oneway_hash, check_domain_rules, check_email_rules, is_valid_ipv4_address, is_valid_ipv6_address
from trivialsec.helpers.config import config
from trivialsec.helpers.payments import checkout, create_customer
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.helpers.transport import Metadata
from trivialsec.models.domain_stat import DomainStat
from trivialsec.models.domain import Domain, Domains
from trivialsec.models.project import Project
from trivialsec.models.service_type import ServiceType
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.known_ip import KnownIp
from trivialsec.models.plan import Plan
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa
from trivialsec.models.account import Account
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.invitation import Invitation
from trivialsec.models.role import Role, Roles
from trivialsec.services.accounts import register
from trivialsec.services.jobs import queue_job
from trivialsec.services.domains import handle_add_domain


logger = logging.getLogger(__name__)
blueprint = Blueprint('api', __name__)

@control_timing_attacks(seconds=2)
@blueprint.route('/test', methods=['GET', 'POST'])
@login_required
@prepared_json
def test(params):
    params['account'] = {'member_id': current_user.member_id}
    params['status'] = 'success'
    params['message'] = f'{request.method} {request.base_url}'
    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/register', methods=['POST'])
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
                    "invitation_message": "Please click the Activation link below, or copy and paste it into a browser if you prefer.",
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

@control_timing_attacks(seconds=2)
@blueprint.route('/registration/webauthn', methods=['POST'])
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

@control_timing_attacks(seconds=2)
@blueprint.route('/registration/totp', methods=['POST'])
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

@control_timing_attacks(seconds=2)
@blueprint.route('/authorization/webauthn', methods=['POST'])
@require_recaptcha(action='authorization_action')
@prepared_json
def api_authorization_webauthn(params):
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

        scratch = oneway_hash(f'{datetime.now()}{member.member_id}')
        member.scratch_code = f'{scratch[:4]}-{scratch[4:10]}-{scratch[10:18]}-{scratch[18:24]}'.upper()
        member.confirmation_url = f"/login/{oneway_hash(f'{random()}{remote_addr}')}"
        member.persist()
        magic_link = f"{config.get_app().get('app_url')}{member.confirmation_url}"
        send_email(
            subject="TrivialSec Magic Link",
            recipient=member.email,
            template='magic-link',
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

@control_timing_attacks(seconds=2)
@blueprint.route('/authorization/totp', methods=['POST'])
@require_recaptcha(action='authorization_action')
@prepared_json
def api_authorization_totp(params):
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

        scratch = oneway_hash(f'{datetime.now()}{member.member_id}')
        member.scratch_code = f'{scratch[:4]}-{scratch[4:10]}-{scratch[10:18]}-{scratch[18:24]}'.upper()
        member.confirmation_url = f"/login/{oneway_hash(f'{random()}{remote_addr}')}"
        member.persist()
        magic_link = f"{config.get_app().get('app_url')}{member.confirmation_url}"
        send_email(
            subject="TrivialSec Magic Link",
            recipient=member.email,
            template='magic-link',
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

@control_timing_attacks(seconds=2)
@blueprint.route('/webauthn/device-name', methods=['POST'])
@require_recaptcha(action='name_device_action')
@prepared_json
def api_name_device(params):
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

@control_timing_attacks(seconds=2)
@blueprint.route('/recovery/mfa', methods=['POST'])
@require_recaptcha(action='recovery_action')
@prepared_json
def api_recover_mfa(params):
    #TODO use MFA not password to save account information
    return jsonify({'message': 'not implemented'})
    if 'scratch_code' not in params:
        params['message'] = messages.ERR_INCORRECT_SCRATCH_CODE

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        member = register(
            account_id=invitee.account_id,
            role_id=invitee.role_id,
            email_addr=invitee.email,
            verified=True
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
        logger.error(err)
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
@blueprint.route('/subscribe', methods=['POST'])
@require_recaptcha(action='subscribe_action')
@prepared_json
def api_subscribe(params):
    if 'email' not in params or not check_email_rules(params.get('email')):
        return jsonify(params)

    try:
        upsert_contact(recipient_email=params.get('email'))
        send_email(
            subject="Subscribed to TrivialSec updates",
            recipient=params.get('email'),
            template='subscriptions',
            group='subscriptions',
            data=dict()
        )
        params['status'] = 'success'
        params['message'] = messages.OK_SUBSCRIBED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/search/<string:model>', methods=['POST'])
@login_required
def api_search(model=None):
    params = request.get_json()
    data = {
        'message': 'cannot find results',
        'status': 'info',
        'id': None
    }
    if model == 'domain':
        domain = Domain(name=params['domain_name'], account_id=current_user.account_id)
        if domain.exists(['name', 'account_id']):
            data['id'] = domain.domain_id
            data['status'] = 'error'
            data['message'] = ''
    elif model == 'project':
        project = Project(name=params['project_name'], account_id=current_user.account_id)
        if project.exists(['name', 'account_id']):
            data['id'] = project.project_id
            data['status'] = 'error'
            data['message'] = ''

    return jsonify(data)

@blueprint.route('/domain-verify/<string:target>', methods=['GET'])
@login_required
def api_domain_verify(target):
    if not check_domain_rules(target):
        return jsonify({
            'error': messages.ERR_VALIDATION_DOMAIN_RULES,
            'registered': False,
            'result': False
        })
    http_metadata = Metadata(url=f'https://{target}').verification_check()
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_DOMAIN_VERIFICATION_CHECK,
        description=f'{target}'
    ).persist()
    return jsonify({
        'error': http_metadata.dns_answer,
        'registered': http_metadata.registered,
        'verification_hash': current_user.account.verification_hash,
        'result': bool(current_user.account.verification_hash == http_metadata.verification_hash)
    })

@blueprint.route('/domain-metadata', methods=['POST'])
@login_required
def api_domain_metadata():
    params = request.get_json()
    domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = messages.ERR_DOMAIN_METADATA_CHECK
        return jsonify(params)

    service_type = ServiceType(name='metadata')
    service_type.hydrate('name')
    queue_job(
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name}
    )

    return jsonify({
        'status': 'success',
        'message': messages.OK_DOMAIN_METADATA_CHECK
    })

@blueprint.route('/domain-dns', methods=['POST'])
@login_required
def api_domain_dns():
    params = request.get_json()
    domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = messages.ERR_ACCESS_DENIED
        return jsonify(params)

    service_type = ServiceType(name='drill')
    service_type.hydrate('name')
    queue_job(
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name}
    )

    return jsonify({
        'status': 'success',
        'message': messages.OK_SCAN_DNS
    })

@blueprint.route('/domain-subdomains', methods=['POST'])
@login_required
def api_domain_subdomains():
    params = request.get_json()
    domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = messages.ERR_ACCESS_DENIED
        return jsonify(params)

    service_type = ServiceType(name='amass')
    service_type.hydrate('name')
    scan_type = 'passive'
    queue_job(
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name, 'scan_type': scan_type}
    )

    return jsonify({
        'status': 'success',
        'message': messages.OK_SCAN_SUBDOMAINS
    })

@blueprint.route('/domain-tls', methods=['POST'])
@login_required
def api_domain_tls():
    params = request.get_json()
    domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = messages.ERR_ACCESS_DENIED
        return jsonify(params)

    scan_type = 'passive'
    domain.get_stats()
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked and domain_stat.domain_stat == DomainStat.APP_VERIFIED and domain_stat.domain_value == '1':
                scan_type = 'active'
                break

    service_type = ServiceType(name='testssl')
    service_type.hydrate('name')
    queue_job(
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name, 'scan_type': scan_type}
    )

    return jsonify({
        'status': 'success',
        'message': messages.OK_SCAN_TLS
    })

@blueprint.route('/create-project', methods=['POST'])
@login_required
def api_create_project():
    params = request.get_json()

    project = Project(name=params.get('project_name'))
    project.account_id = current_user.account_id
    if project.exists(['name']):
        project.hydrate()
        project.deleted = False

    target = params.get('domain_name')
    if not is_valid_ipv4_address(target) and not is_valid_ipv6_address(target) and not check_domain_rules(target):
        params['status'] = 'error'
        params['message'] = f'{target} is an invalid target'
        return jsonify(params)

    project.persist()
    params['project_id'] = project.project_id
    if is_valid_ipv4_address(target) or is_valid_ipv6_address(target):
        knownip = KnownIp(ip_address=target)
        if not knownip.exists(['ip_address', 'project_id']):
            knownip.account_id = current_user.account.account_id
            knownip.project_id = project.project_id
            knownip.source = 'create_project'
            knownip.ip_version = 'ipv4' if is_valid_ipv4_address(target) else 'ipv6'
            if knownip.persist():
                ActivityLog(
                    member_id=current_user.member_id,
                    action=ActivityLog.ACTION_ADDED_IPADDRESS,
                    description=target
                ).persist()

        knownip_dict = {}
        for col in knownip.cols():
            knownip_dict[col] = getattr(knownip, col)
        params['ip_address'] = knownip_dict

    domain = None
    if check_domain_rules(target):
        domain = handle_add_domain(domain_name=target, project=project, current_user=current_user)

    if not isinstance(domain, Domain):
        params['status'] = 'error'
        params['message'] = messages.ERR_DOMAIN_ADD
        return jsonify(params)

    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_ADDED_DOMAIN,
        description=domain.name
    ).persist()
    domain_dict = {}
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    params['domain'] = domain_dict

    metadata = ServiceType(name='metadata')
    metadata.hydrate('name')
    queue_job(
        service_type=metadata,
        priority=3,
        member=current_user,
        project=project,
        params={'target': domain.name},
        scan_next=['amass', 'testssl']
    )
    drill = ServiceType(name='drill')
    drill.hydrate('name')
    queue_job(
        service_type=drill,
        priority=1,
        member=current_user,
        project=project,
        params={'target': domain.name},
        on_demand=False
    )

    params['status'] = 'success'
    params['message'] = messages.OK_ADDED_DOMAIN

    return jsonify(params)

@blueprint.route('/update-email', methods=['POST'])
@login_required
def api_update_email():
    #TODO use MFA not password to save account information
    return jsonify({'message': 'not implemented'})
    errors = []
    params = request.get_json()
    params['status'] = 'info'
    params['message'] = 'Email update not available at this time'

    check_member = Member(email=params.get('email'))
    if check_member.exists(['email']):
        errors.append(messages.ERR_MEMBER_EXIST)

    if 'email' not in params or not check_email_rules(params.get('email')):
        errors.append(messages.ERR_VALIDATION_EMAIL_RULES)

    if not check_encrypted_password(params.get('password'), current_user.password):
        errors.append(messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    current_user.email = params.get('email')
    current_user.verified = False
    current_user.confirmation_sent = False
    current_user.confirmation_url = f"/confirmation/{oneway_hash(params.get('email'))}"
    current_user.persist()
    confirmation_url = f"{config.get_app().get('app_url')}{current_user.confirmation_url}"
    try:
        send_email(
            subject="TrivialSec - email address updated",
            recipient=params.get('email'),
            template='updated_email',
            data={
                "activation_url": confirmation_url
            }
        )
        current_user.confirmation_sent = True
        if current_user.persist():
            if request.headers.getlist("X-Forwarded-For"):
                remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
            else:
                remote_addr = request.remote_addr
            ActivityLog(
                member_id=current_user.member_id,
                action=ActivityLog.ACTION_USER_CHANGE_EMAIL_REQUEST,
                description=f'{remote_addr}\t{request.user_agent}'
            ).persist()
            params['status'] = 'success'
            params['message'] = messages.OK_EMAIL_UPDATE
        return jsonify(params)

    except Exception as ex:
        logger.exception(ex)
        params['error'] = str(ex)
        errors.append(messages.ERR_EMAIL_NOT_SENT)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)

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
        invitation.message = params.get('invite_message', 'Trivial Security monitors public threats and easy attack vectors so you don\'t have to spend your valuable time keeping up-to-date daily.')
        invitation.confirmation_url = f"/confirmation/{oneway_hash(params['invite_email'])}"

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

@blueprint.route('/account', methods=['POST'])
@login_required
def api_account():
    #TODO use MFA not password to save account information
    return jsonify({'message': 'not implemented'})

    params = request.get_json()
    changes = []
    err = None
    responses = []
    protected = ['verification_hash', 'registered', 'socket_key', 'plan_id', 'account_id', 'password']
    params_keys = set()
    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'alias' and current_user.account.alias == param.get('value'):
            responses.append(f"{param.get('prop')} unchanged")
            continue
        if param.get('prop') == 'billing_email':
            password = [i['value'] for i in params if i['prop'] == 'password'][0] or None
            if password is None:
                err = 'password was not provided when changing the billing email'
                responses.append(err)
                break
            if not check_password_policy(password) or not \
                check_encrypted_password(password, current_user.password):
                err = messages.ERR_VALIDATION_PASSWORD_POLICY
                responses.append(err)
                break

        params_keys.add(param.get('prop'))
        from_value = getattr(current_user.account, param.get('prop'))
        setattr(current_user.account, param.get('prop'), param.get('value'))
        changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")

    res = None
    if len(changes) > 0:
        res = current_user.account.persist()
    if res is False:
        err = f'Error saving {" ".join(params_keys)}'
        responses.append(messages.ERR_ACCOUNT_UPDATE)
    if res is True:
        responses.append(messages.OK_ACCOUNT_UPDATED)
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_USER_CHANGED_ACCOUNT,
            description='\t'.join(changes)
        ).persist()

    account_dict = {}
    for col in current_user.account.cols():
        account_dict[col] = getattr(current_user.account, col)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': "\n".join(responses),
        'account': account_dict,
        'result': err is None
    })

@blueprint.route('/account-config', methods=['POST'])
@login_required
def api_account_config():
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

@blueprint.route('/setup-account', methods=['POST'])
@login_required
def api_setup_account():
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

@blueprint.route('/organisation/member', methods=['POST'])
@login_required
def api_organisation_member():
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
        member.confirmation_url = f"/confirmation/{oneway_hash(params.get('email'))}"
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

@blueprint.route('/archive-project', methods=['POST'])
@login_required
def api_archive_project():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    project = Project(
        account_id=current_user.account_id,
        project_id=int(params.get('project_id'))
    )
    project.hydrate(['account_id', 'project_id'])
    if not isinstance(project, Project):
        return abort(403)

    project.deleted = True
    project.persist()
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_DELETE_PROJECT,
        description=project.name
    ).persist()
    domains = Domains()
    for domain in domains.find_by([('account_id', current_user.account_id), ('project_id', project.project_id)], limit=1000):
        domain.deleted = True
        domain.enabled = False
        domain.persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_PROJECT_DELETE
    })

@blueprint.route('/enable-domain', methods=['POST'])
@login_required
def api_enable_domain():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    domain = Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, Domain):
        return abort(403)

    domain.enabled = True
    domain.persist()
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_ENABLE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_DOMAIN_ENABLED
    })

@blueprint.route('/disable-domain', methods=['POST'])
@login_required
def api_disable_domain():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    domain = Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, Domain):
        return abort(403)

    domain.enabled = False
    domain.persist()
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_DISABLE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_DOMAIN_DISABLED
    })

@blueprint.route('/delete-domain', methods=['POST'])
@login_required
def api_delete_domain():
    #TODO
    return jsonify({'message': 'not implemented'})
    params = request.get_json()
    domain = Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, Domain):
        return abort(403)

    domain.deleted = True
    domain.persist()
    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_DELETE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_DOMAIN_DELETE
    })

@control_timing_attacks(seconds=2)
@blueprint.route('/magic-link', methods=['POST'])
@require_recaptcha(action='public_action')
@prepared_json
def api_login_magic_link(params):
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
        template='magic-link',
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
