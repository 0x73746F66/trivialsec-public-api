from flask import Blueprint, jsonify, request, abort
from flask_login import current_user, login_required
from gunicorn.glogging import logging
from trivialsec.decorators import control_timing_attacks, prepared_json
from trivialsec.helpers import messages, check_domain_rules, is_valid_ipv4_address, is_valid_ipv6_address
from trivialsec.models.domain import Domain, Domains
from trivialsec.models.project import Project
from trivialsec.models.job_run import JobRuns
from trivialsec.models.service_type import ServiceType
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.known_ip import KnownIp
from trivialsec.services.jobs import queue_job
from trivialsec.services.domains import handle_add_domain


logger = logging.getLogger(__name__)
blueprint = Blueprint('project', __name__)

@blueprint.route('/create', methods=['POST'])
@control_timing_attacks(seconds=2)
@login_required
def api_create_project():
    params = request.get_json()
    project_name = params.get('project_name')
    project = Project(name=project_name)
    project.gen_canonical_id()
    project.account_id = current_user.account_id
    if project.exists(['canonical_id']):
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

    amass = ServiceType(name='amass')
    amass.hydrate('name')
    queue_job(
        service_type=amass,
        priority=1,
        member=current_user,
        project=project,
        params={'target': domain.name},
        scan_next={
            'new': {
                'target_type': 'domain',
                'service_types': ['amass', 'nmap', 'metadata', 'drill']
            },
            'target': {
                'service_types': []
            }
        }
    )
    nmap = ServiceType(name='nmap')
    nmap.hydrate('name')
    queue_job(
        service_type=nmap,
        priority=1,
        member=current_user,
        project=project,
        params={'target': domain.name},
        scan_next={
            'new': {
                'target_type': 'port',
                'service_types': ['testssl']
            },
            'target': {
                'service_types': ['testssl']
            }
        }
    )
    metadata = ServiceType(name='metadata')
    metadata.hydrate('name')
    queue_job(
        service_type=metadata,
        priority=1,
        member=current_user,
        project=project,
        params={'target': domain.name}
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

@blueprint.route('/archive', methods=['POST'])
@control_timing_attacks(seconds=2)
@login_required
@prepared_json
def api_archive_project(params):
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

    for domain in Domains().find_by([('account_id', current_user.account_id), ('project_id', project.project_id)], limit=1000):
        domain.deleted = True
        domain.enabled = False
        domain.persist()

    for job in JobRuns().find_by([('account_id', current_user.account_id), ('project_id', project.project_id)], limit=1000):
        if job.state not in [ServiceType.STATE_COMPLETED, ServiceType.STATE_FINALISING, ServiceType.STATE_PROCESSING, ServiceType.STATE_STARTING]:
            job.delete()

    return jsonify({
        'status': 'success',
        'message': messages.OK_PROJECT_DELETE
    })
