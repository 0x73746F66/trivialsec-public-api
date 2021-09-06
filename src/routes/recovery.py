from random import random
from flask import Blueprint, jsonify, current_app as app
from flask_login import current_user, login_required
from gunicorn.glogging import logging

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json, require_authz
from trivialsec.helpers import messages, oneway_hash, check_email_rules
from trivialsec.helpers.config import config
from trivialsec.helpers.sendgrid import send_email
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.member import Member, Members
from trivialsec.models.account import Account
from trivialsec.models.invitation import Invitation
from trivialsec.models.role import Role


logger = logging.getLogger(__name__)
blueprint = Blueprint('recovery', __name__)

@blueprint.route('/scratch', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='recovery_action')
@prepared_json
def api_recover_scratch(params):
    if params.get('scratch_code') is None:
        params['message'] = messages.ERR_EMAIL_NOT_SENT
        return jsonify(params)

    try:
        member = Member()
        member.scratch_code = params.get('scratch_code')
        if not member.exists(['scratch_code']) or not member.member_id:
            logger.info(f"scratch_code {params.get('scratch_code')} not found")
            params['message'] = messages.ERR_EMAIL_NOT_SENT
            return jsonify(params)

        member.hydrate()
        confirmation_hash = oneway_hash(f'{random()}{member.account_id}')
        member.confirmation_url = f"/confirmation/{confirmation_hash}"
        member.persist()
        send_email(
            subject="TrivialSec - Account Recovery",
            recipient=member.email,
            template='account_recovery',
            data={
                "activation_url": f"{config.get_app().get('app_url')}{member.confirmation_url}"
            }
        )
        member.confirmation_sent = True
        member.persist()
        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_RECOVERY_CODE_USED,
            description=member.scratch_code
        ).persist()
        params['status'] = 'success'
        params['message'] = messages.OK_RECOVERY_EMAIL

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/email', methods=['POST'])
@control_timing_attacks(seconds=2)
@require_recaptcha(action='recovery_action')
@prepared_json
def api_recover_email(params):
    if not check_email_rules(params.get('old_email')) or not check_email_rules(params.get('new_email')):
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    try:
        check_member = Member()
        check_member.email = params.get('new_email')
        if check_member.exists(['email']):
            logger.info(f"new_email {params.get('new_email')} exists")
            params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
            return jsonify(params)

        member = Member()
        member.email = params.get('old_email')
        if not member.exists(['email']) or not member.member_id:
            logger.info(f"old_email {params.get('old_email')} not found")
            params['message'] = messages.ERR_EMAIL_NOT_SENT
            return jsonify(params)

        member.hydrate()
        params['owners'] = []
        for org_member in Members().find_by_role_id(role_id=Role.ROLE_OWNER_ID, account_id=member.account_id):
            if org_member.email == params.get('new_email') or org_member.email == params.get('old_email'):
                continue
            params['owners'].append(org_member.email)

        if len(params['owners']) == 0:
            logger.info("No owners available")
            params['message'] = messages.ERR_OWNER_RECOVERY
            return jsonify(params)

        invitation = Invitation()
        invitation.email = params.get('new_email')
        if invitation.exists(['email']):
            invitation.hydrate()
        if invitation.account_id != member.account_id:
            invitation.invitation_id = None
            invitation.account_id = member.account_id

        invitation.role_id = Role.ROLE_RO_ID
        confirmation_hash = oneway_hash(f'{random()}{member.account_id}')
        invitation.confirmation_url = f"/confirmation/{confirmation_hash}"
        invitation.exists(['confirmation_url'])
        invitation.persist()

        account = Account()
        account.account_id = member.account_id
        account.hydrate()
        for owner_email in params['owners']:
            send_email(
                subject="Trivial Security - User requested account recovery",
                recipient=owner_email,
                template='recovery_request',
                data={
                    "org": account.alias,
                    "new_email": params.get('new_email'),
                    "old_email": params.get('old_email'),
                    "accept_url": f"{config.get_app().get('app_url')}/invitation-request/approve/{confirmation_hash}",
                    "deny_url": f"{config.get_app().get('app_url')}/invitation-request/deny/{confirmation_hash}"
                }
            )

        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_RECOVERY_REQUEST,
            description=f"{params.get('old_email')} requested recovery to: {params.get('new_email')}"
        ).persist()
        params['status'] = 'success'
        params['message'] = messages.OK_REQUEST_RECOVERY

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@blueprint.route('/regenerate-scratch', methods=['GET'])
@login_required
@require_authz
@prepared_json
def api_regenerate_scratch(params):
    try:
        member = Member()
        member.member_id = current_user.member_id
        if not member.exists():
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        if not member.hydrate():
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        from_value = member.scratch_code
        scratch = oneway_hash(f'{random()}{member.member_id}')
        member.scratch_code = f'{scratch[:4]}-{scratch[4:10]}-{scratch[10:18]}-{scratch[18:24]}'.upper()
        member.persist()
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_RECOVERY_CODE_CHANGED,
            description=f"scratch_code updated from {from_value} to {member.scratch_code}"
        ).persist()
        params['scratch_code'] = member.scratch_code
        params['status'] = 'success'
        params['message'] = messages.OK_GENERIC

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)
