import json
from datetime import datetime
from flask import Blueprint, jsonify, request, abort
from flask_login import current_user, login_required
from gunicorn.glogging import logging
from trivialsec.decorators import control_timing_attacks, prepared_json
from trivialsec.helpers import messages, check_domain_rules
from trivialsec.helpers.transport import Metadata
from trivialsec.models.domain_stat import DomainStat
from trivialsec.models.domain import Domain
from trivialsec.models.project import Project
from trivialsec.models.job_run import JobRuns
from trivialsec.models.service_type import ServiceType
from trivialsec.models.activity_log import ActivityLog
from trivialsec.services.jobs import queue_job, QueueData


logger = logging.getLogger(__name__)
blueprint = Blueprint('api', __name__)

# @blueprint.route('/verify/<string:target>', methods=['GET'])
# @control_timing_attacks(seconds=2)
# @login_required
# def api_domain_verify(target):
#     if not check_domain_rules(target):
#         return jsonify({
#             'error': messages.ERR_VALIDATION_DOMAIN_RULES,
#             'registered': False,
#             'result': False
#         })
#     http_metadata = Metadata(url=f'https://{target}').verification_check()
#     ActivityLog(
#         member_id=current_user.member_id,
#         action=ActivityLog.ACTION_DOMAIN_VERIFICATION_CHECK,
#         description=f'{target}'
#     ).persist()
#     return jsonify({
#         'error': http_metadata.dns_answer,
#         'registered': http_metadata.registered,
#         'verification_hash': current_user.account.verification_hash,
#         'result': bool(current_user.account.verification_hash == http_metadata.verification_hash)
#     })

# @blueprint.route('/queue/metadata', methods=['POST'])
# @control_timing_attacks(seconds=2)
# @login_required
# def api_domain_metadata():
#     params = request.get_json()
#     domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
#     domain.hydrate(['domain_id', 'account_id'])
#     project = Project(project_id=domain.project_id)
#     if not project.hydrate():
#         params['status'] = 'error'
#         params['message'] = messages.ERR_DOMAIN_METADATA_CHECK
#         return jsonify(params)

#     service_type = ServiceType(name='metadata')
#     service_type.hydrate('name')
#     queue_job(
#         service_type=service_type,
#         member=current_user,
#         project=project,
#         priority=2,
#         params={'target': domain.name}
#     )

#     return jsonify({
#         'status': 'success',
#         'message': messages.OK_DOMAIN_METADATA_CHECK
#     })

# @blueprint.route('/queue/dns', methods=['POST'])
# @control_timing_attacks(seconds=2)
# @login_required
# def api_domain_dns():
#     params = request.get_json()
#     domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
#     domain.hydrate(['domain_id', 'account_id'])
#     project = Project(project_id=domain.project_id)
#     if not project.hydrate():
#         params['status'] = 'error'
#         params['message'] = messages.ERR_ACCESS_DENIED
#         return jsonify(params)

#     service_type = ServiceType(name='drill')
#     service_type.hydrate('name')
#     queue_job(
#         service_type=service_type,
#         member=current_user,
#         project=project,
#         priority=2,
#         params={'target': domain.name}
#     )

#     return jsonify({
#         'status': 'success',
#         'message': messages.OK_SCAN_DNS
#     })

# @blueprint.route('/queue/subdomains', methods=['POST'])
# @control_timing_attacks(seconds=2)
# @login_required
# def api_domain_subdomains():
#     params = request.get_json()
#     domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
#     domain.hydrate(['domain_id', 'account_id'])
#     project = Project(project_id=domain.project_id)
#     if not project.hydrate():
#         params['status'] = 'error'
#         params['message'] = messages.ERR_ACCESS_DENIED
#         return jsonify(params)

#     service_type = ServiceType(name='amass')
#     service_type.hydrate('name')
#     scan_type = 'passive'
#     queue_job(
#         service_type=service_type,
#         member=current_user,
#         project=project,
#         priority=2,
#         params={'target': domain.name, 'scan_type': scan_type}
#     )

#     return jsonify({
#         'status': 'success',
#         'message': messages.OK_SCAN_SUBDOMAINS
#     })

# @blueprint.route('/queue/tls', methods=['POST'])
# @control_timing_attacks(seconds=2)
# @login_required
# def api_domain_tls():
#     params = request.get_json()
#     domain = Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
#     domain.hydrate(['domain_id', 'account_id'])
#     project = Project(project_id=domain.project_id)
#     if not project.hydrate():
#         params['status'] = 'error'
#         params['message'] = messages.ERR_ACCESS_DENIED
#         return jsonify(params)

#     scan_type = 'passive'
#     domain.get_stats()
#     for domain_stat in domain.stats:
#         if domain_stat.domain_stat == DomainStat.HTTP_LAST_CHECKED:
#             setattr(domain, DomainStat.HTTP_LAST_CHECKED, domain_stat.domain_value)
#             break

#     if hasattr(domain, DomainStat.HTTP_LAST_CHECKED):
#         http_last_checked = datetime.fromisoformat(getattr(domain, DomainStat.HTTP_LAST_CHECKED)).replace(microsecond=0)
#         for domain_stat in domain.stats:
#             created_at = datetime.fromisoformat(domain_stat.created_at)
#             if created_at == http_last_checked and domain_stat.domain_stat == DomainStat.APP_VERIFIED and domain_stat.domain_value == '1':
#                 scan_type = 'active'
#                 break

#     service_type = ServiceType(name='testssl')
#     service_type.hydrate('name')
#     queue_job(
#         service_type=service_type,
#         member=current_user,
#         project=project,
#         priority=2,
#         params={'target': domain.name, 'scan_type': scan_type}
#     )

#     return jsonify({
#         'status': 'success',
#         'message': messages.OK_SCAN_TLS
#     })

@blueprint.route('/enable', methods=['POST'])
@control_timing_attacks(seconds=2)
@login_required
@prepared_json
def api_enable_domain(params):
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

@blueprint.route('/disable', methods=['POST'])
@control_timing_attacks(seconds=2)
@login_required
@prepared_json
def api_disable_domain(params):
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

@blueprint.route('/delete', methods=['POST'])
@control_timing_attacks(seconds=2)
@login_required
@prepared_json
def api_delete_domain(params):
    domain = Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, Domain):
        return abort(403)

    domain.deleted = True
    domain.enabled = False
    domain.persist()
    cancellable_states = [ServiceType.STATE_COMPLETED, ServiceType.STATE_FINALISING, ServiceType.STATE_PROCESSING, ServiceType.STATE_STARTING]
    for job in JobRuns().find_by([('account_id', current_user.account_id), ('project_id', domain.project_id)], limit=1000):
        queue_data = QueueData(**json.loads(job.queue_data))
        if job.state not in cancellable_states and queue_data.target.endswith(domain.name):
            job.delete()

    ActivityLog(
        member_id=current_user.member_id,
        action=ActivityLog.ACTION_DELETE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': messages.OK_DOMAIN_DELETE
    })
