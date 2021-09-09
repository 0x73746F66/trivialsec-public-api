from flask import Blueprint, jsonify, abort
from flask_login import current_user, login_required
from gunicorn.glogging import logging
from trivialsec.decorators import control_timing_attacks, prepared_json
from trivialsec.helpers import messages, check_domain_rules
from trivialsec.models.domain import Domain, Domains, DomainMonitor
from trivialsec.models.project import Project
from trivialsec.models.job_run import JobRuns
from trivialsec.models.service_type import ServiceType
from trivialsec.models.activity_log import ActivityLog
from trivialsec.services.domains import upsert_domain


logger = logging.getLogger(__name__)
blueprint = Blueprint('project', __name__)

@blueprint.route('/create', methods=['POST'])
@login_required
@prepared_json
def api_create_project(params):
    project_name = params.get('project_name')
    domain_name = params.get('domain_name')
    if not project_name or not domain_name:
        params['message'] = 'You must provide both project and domain names'
        return jsonify(params)
    project = Project(name=project_name)
    project.gen_canonical_id()
    project.account_id = current_user.account_id
    project_exists = False
    if project.exists(['canonical_id']):
        project_exists = True
        project.hydrate()
        project.deleted = False

    if not check_domain_rules(domain_name):
        params['message'] = f'{domain_name} isn\'t a valid domain'
        return jsonify(params)
    if project_exists is False:
        project.persist(exists=project_exists)
    params['project_id'] = project.canonical_id
    domain = Domain()
    domain.domain_name = domain_name
    try:
        if domain.exists(f'domain_name:"{domain_name}"'):
            params['status'] = 'info'
            params['message'] = f'{domain_name} is already included in project {project.name}'
            return jsonify(params)

    except Exception as ex:
        logger.exception(ex)
        params['error'] = str(ex)
        params['message'] = 'There was a system error interacting with the domain document'
        return jsonify(params)

    domain_monitor = DomainMonitor()
    domain_monitor.domain_name = domain_name
    domain_monitor.enabled = False
    domain_monitor.project_id = project.project_id
    domain_monitor.account_id = current_user.account_id
    domain_monitor_exists = domain_monitor.exists(['domain_name', 'project_id'])
    if domain_monitor_exists is False and not domain_monitor.persist(exists=domain_monitor_exists):
        params['message'] = 'There was a system error saving domain monitoring'
        return jsonify(params)

    try:
        if not upsert_domain(domain, member=current_user, project=project):
            params['message'] = 'There was a system error saving the domain document'
            return jsonify(params)

    except Exception as ex:
        logger.exception(ex)
        params['error'] = str(ex)
        params['message'] = 'There was a system error saving the domain document'
        return jsonify(params)

    params['domain'] = domain.get_doc()
    params['status'] = 'success'
    params['message'] = messages.OK_ADDED_PROJECT if project_exists is True else messages.OK_UPDATE_PROJECT

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

    for domain in Domains().search(f'account_id:"{current_user.account_id}" AND project_id:"{project.project_id}"'):
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
