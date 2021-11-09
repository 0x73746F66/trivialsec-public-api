from flask import Blueprint, jsonify, request, current_app as app
from flask_login import login_required
from gunicorn.glogging import logging
from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json
from trivialsec.helpers import messages, check_email_rules
from trivialsec.helpers.sendgrid import send_email, upsert_contact


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
        'params': params
    }
    return jsonify(data)
