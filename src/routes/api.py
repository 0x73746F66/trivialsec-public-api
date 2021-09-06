import json
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

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json, require_authz
from trivialsec.helpers import messages, oneway_hash, check_domain_rules, check_email_rules, is_valid_ipv4_address, is_valid_ipv6_address
from trivialsec.helpers.config import config
from trivialsec.helpers.authz import get_authorization_token, start_transaction, is_active_transaction
from trivialsec.helpers.payments import checkout, create_customer
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.helpers.transport import Metadata
from trivialsec.models.domain_stat import DomainStat
from trivialsec.models.domain import Domain, Domains
from trivialsec.models.project import Project
from trivialsec.models.job_run import JobRuns
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
from trivialsec.services.jobs import queue_job, QueueData
from trivialsec.services.domains import handle_add_domain


logger = logging.getLogger(__name__)
blueprint = Blueprint('api', __name__)

@blueprint.route('/subscribe', methods=['POST'])
@control_timing_attacks(seconds=2)
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
