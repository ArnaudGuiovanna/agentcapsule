#!/usr/bin/env python3
"""Run the two-member MonApp HTTP conformance journey in a disposable tenant."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
from urllib import error, parse, request
from uuid import uuid4


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('unexpected API redirect')


class MonApp:
    def __init__(self, config):
        self.url = config['api'].rstrip('/')
        parts = parse.urlsplit(self.url)
        if parts.scheme != 'https' or parts.username or not parts.hostname:
            raise ValueError('HTTPS API URL required')
        self.client = request.build_opener(NoRedirect(), request.HTTPSHandler(
            context=ssl.create_default_context(cafile=config.get('api_ca'))))

    def call(self, token, method, path, body=None, status=200, key=None):
        headers = {'Authorization': 'Bearer ' + token}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers.update({'Idempotency-Key': key or str(uuid4()), 'Content-Type': 'application/json'})
        req = request.Request(self.url + '/v1/' + path, data, headers, method=method)
        try:
            response = self.client.open(req, timeout=20)
        except error.HTTPError as err:
            response = err
        with response:
            obj = json.load(response)
            if response.code != status:
                raise RuntimeError(f'{method} {path}: {response.code} ({obj.get("code")}), expected {status}')
            return obj

    def wait(self, token, path, terminal, pending, timeout):
        stop = time.monotonic() + timeout
        while True:
            obj = self.call(token, 'GET', path)
            if obj['state'] == terminal:
                return obj
            if obj['state'] not in pending or time.monotonic() >= stop:
                raise RuntimeError(f'{path}: {obj["state"]} ({obj.get("reason", "")})')
            time.sleep(max(0.2, min(5, obj.get('retry_after_seconds', 1))))


def credential(path):
    source = Path(path)
    if os.name != 'nt' and source.stat().st_mode & 0o077:
        raise ValueError('token files must be private')
    return source.read_text().strip()


def problem(response, code):
    if response.get('code') != code:
        raise RuntimeError(f'expected problem {code}, received {response.get("code")}')


def live_claims(token):
    # Members supply JWT access tokens. Check the fixture preconditions here.
    # Every authenticated request still relies on the PaaS to verify the signature.
    body = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
    if claims['exp'] <= time.time():
        raise ValueError('renew the expired member token file')
    return claims


def verify_revoked(config, report):
    """Reopen a connection and inspect the recorded outcome, including after a restart."""
    api = MonApp(config)
    admin = credential(config['admin_token_file'])
    foreign = credential(config['other_org_token_file'])
    app = 'applications/' + report['application_id']
    if api.call(admin, 'GET', app)['status'] != 'disabled':
        raise RuntimeError('revoked application is active')
    for activation in report['activations']:
        state = api.call(admin, 'GET', app + '/activations/' + activation)
        if state['state'] != 'disabled':
            raise RuntimeError('revoked activation regained access')
    for member in config['members']:
        token = credential(member['token_file'])
        claims = live_claims(token)
        if (claims['iss'] != config['application']['issuer'] or
                (claims.get('client_id') or claims.get('azp')) != config['application']['client_id']):
            raise ValueError('supply a current member token issued for the registered MonApp client')
        problem(api.call(token, 'GET', 'agents', status=401), 'authentication_required')
    receipts = report.get('transfer', {}).get('revocations', []) + report['revocations'] + report['application_revocations']
    states = {}
    for receipt in receipts:
        path = 'access-revocations/' + receipt['id']
        current = api.call(admin, 'GET', path)
        if (current['id'] != receipt['id'] or current['kind'] != receipt['kind'] or
                current['state'] not in ('pending', 'confirmed') or
                receipt['state'] == 'confirmed' and current['state'] != 'confirmed'):
            raise RuntimeError('revocation receipt changed identity or regressed')
        states[current['id']] = current['state']
        problem(api.call(foreign, 'GET', path, status=404), 'not_found')
    return {'application_id': report['application_id'], 'status': 'disabled', 'receipt_states': states}


def check_pool_refusal(api, admin, token, app_id, email, pool):
    """Use a dedicated pool with exactly one eligible agent and request two slots."""
    app = 'applications/' + app_id
    path = 'pools/' + pool
    before = api.call(admin, 'GET', path)
    if before['available'] + before['preparing'] != 1:
        raise ValueError('refusal_pool_id must have exactly one unassigned agent')
    slots = [{'name': name, 'pool_id': pool, 'permissions': ['read_metadata']} for name in ('first', 'second')]
    policy = api.call(admin, 'POST', 'assignment-policies/plan',
                      {'application_id': app_id, 'on_exhaustion': 'refuse', 'slots': slots}, 201)
    api.call(admin, 'POST', f'assignment-policies/{policy["id"]}/apply', {})
    invitation = api.call(admin, 'POST', app + '/invitations', {'email': email, 'policy_id': policy['id'],
                          'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}, 201)
    problem(api.call(token, 'POST', app + '/accept', {'proof': invitation['proof']}, 409), 'pool_exhausted')
    after = api.call(admin, 'GET', path)
    if after['available'] + after['preparing'] != 1:
        raise RuntimeError('refused activation consumed a pool agent')


def sign_in_again(config, member, previous):
    """Obtain another browser session with the bundled realm after a lifecycle event."""
    options = member['keycloak_login']
    app = config['application']
    with TemporaryDirectory() as directory:
        token_path = Path(directory, 'access.jwt')
        args = [sys.executable, str(Path(__file__).with_name('oidc-login.py')),
                '--issuer', app['issuer'], '--client-id', app['client_id'],
                '--redirect-uri', options.get('redirect_uri', app['redirect_uris'][0]),
                '--username', options['username'], '--password-file', options['password_file'],
                '--output', str(token_path)]
        if options.get('ca_file'):
            args.extend(['--ca-file', options['ca_file']])
        subprocess.run(args, check=True)
        token = credential(token_path)
    before, after = live_claims(previous), live_claims(token)
    audience = after['aud'] if isinstance(after['aud'], list) else [after['aud']]
    if (token == previous or after['iss'] != app['issuer'] or after['sub'] != before['sub'] or
            app['audience'] not in audience or (after.get('azp') or after.get('client_id')) != app['client_id'] or
            'agent:read' not in after.get('scope', '').split() or
            (before.get('sid') and (not after.get('sid') or before['sid'] == after['sid']))):
        raise ValueError('expected a separate session for the same member and client')
    return token


def invoke_and_read(api, token, agent, text, timeout):
    response = api.call(token, 'POST', 'agents/' + agent + '/invocations',
                        {'content': [{'type': 'text', 'text': text}]}, 202)
    path = 'invocations/' + response['id']
    api.wait(token, path, 'completed', ('accepted', 'scheduled', 'working'), timeout)
    api.call(token, 'GET', path + '/result')
    return response['id']


def verify(config):
    api = MonApp(config)
    admin = credential(config['admin_token_file'])
    foreign = credential(config['other_org_token_file'])
    members = config['members']
    if len(members) != 2:
        raise ValueError('supply two distinct test members')
    tokens = [credential(m['token_file']) for m in members]
    registration = api.call(admin, 'POST', 'applications', config['application'], 201)
    app = 'applications/' + registration['id']
    backend = registration['provisioning_token']
    team, shared = config['support_team_id'], config['support_agent_id']
    sales = config.get('sales_team_id') or api.call(admin, 'POST', 'teams', {'name': 'Sales ' + str(uuid4())}, 201)['id']
    sales_agent = config.get('sales_agent_id')
    if sales == team or sales_agent == shared:
        raise ValueError('use distinct Support and Sales teams and shared agents')
    perms = ['read_metadata', 'invoke', 'read_content']
    personal = {'personal': config['pool_id']}
    if config.get('second_personal_pool_id'):
        personal['research'] = config['second_personal_pool_id']
    if config.get('refusal_pool_id'):
        check_pool_refusal(api, admin, tokens[0], registration['id'], members[0]['email'], config['refusal_pool_id'])
    slots = [{'name': name, 'pool_id': pool, 'permissions': perms} for name, pool in personal.items()]
    slots.append({'name': 'support', 'team_id': team, 'agent_id': shared, 'permissions': perms})
    if sales_agent:
        slots.append({'name': 'sales', 'team_id': sales, 'agent_id': sales_agent, 'permissions': perms})
    plan = api.call(admin, 'POST', 'assignment-policies/plan', {
        'application_id': registration['id'], 'on_exhaustion': 'refuse', 'allowed_teams': [team, sales],
        'slots': slots}, 201)
    api.call(admin, 'POST', f'assignment-policies/{plan["id"]}/apply', {})
    def invite(member, seconds):
        return {'policy_id': plan['id'], 'team_id': team, 'email': member['email'],
                'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()}

    expiring = invite(members[0], 5)
    short = api.call(admin, 'POST', app + '/invitations', expiring, 201)
    expires = datetime.fromisoformat(expiring['expires_at'])
    if datetime.fromisoformat(short['expires_at'].replace('Z', '+00:00')) != expires:
        raise RuntimeError('invitation was issued with a different expiration')
    problem(api.call(foreign, 'GET', app, status=404), 'not_found')
    problem(api.call(foreign, 'POST', app + '/invitations', invite(members[0], 3600), 404), 'not_found')
    key = str(uuid4())
    invitations = [api.call(admin, 'POST', app + '/invitations', invite(members[0], 3600), 201, key)]
    conflict = api.call(admin, 'POST', app + '/invitations', invite(members[1], 3600), 422, key)
    problem(conflict, 'idempotency_key_reused')
    invitations.append(api.call(admin, 'POST', app + '/invitations', invite(members[1], 3600), 201))
    wrong = {'proof': invitations[0]['proof']}
    problem(api.call(tokens[1], 'POST', app + '/accept', wrong, 404), 'not_found')
    if config.get('wrong_audience_token_file'):
        token = credential(config['wrong_audience_token_file'])
        claims = live_claims(token)
        audience = claims['aud']
        if (claims['iss'] != config['application']['issuer'] or
                config['application']['audience'] in (audience if isinstance(audience, list) else [audience])):
            raise ValueError('supply an access token for another audience of the registered issuer')
        problem(api.call(token, 'POST', app + '/accept', wrong, 401), 'authentication_required')
    time.sleep(max(0, expires.timestamp() - time.time() + 0.2))
    problem(api.call(tokens[0], 'POST', app + '/accept', {'proof': short['proof']}, 409), 'expired')

    def accept(i):
        data = {'proof': invitations[i]['proof']}
        key = str(uuid4())
        first = api.call(tokens[i], 'POST', app + '/accept', data, key=key)
        for replay_key in (key, str(uuid4())):
            replay = api.call(tokens[i], 'POST', app + '/accept', data, key=replay_key)
            for field in ('id', 'principal_id', 'policy_id', 'agents'):
                if replay[field] != first[field]:
                    raise RuntimeError(f'acceptance replay changed {field}')
        return api.wait(backend, app + '/activations/' + first['id'], 'ready',
                        ('waiting_capacity', 'preparing'), config.get('timeout_seconds', 180))

    with ThreadPoolExecutor(max_workers=2) as workers:
        alice, bob = workers.map(accept, range(2))
    distinct = {activation['agents'][name] for activation in (alice, bob) for name in personal}
    if (len(distinct) != 2 * len(personal) or shared in distinct or
            any(a['agents']['support'] != shared for a in (alice, bob))):
        raise RuntimeError('incorrect personal/shared allocation')
    problem(api.call(tokens[1], 'POST', app + '/accept', wrong, 404), 'not_found')
    if config.get('reassigned_email_token_file'):
        # Former holder of Alice's verified email, with a different subject.
        other = credential(config['reassigned_email_token_file'])
        original, replacement = live_claims(tokens[0]), live_claims(other)
        if (replacement['iss'] != original['iss'] or replacement['sub'] == original['sub'] or
                replacement.get('email_verified') is not True or replacement.get('email') != original['email'] or
                'member:accept' not in replacement.get('scope', '').split()):
            raise ValueError("supply a different subject with Alice's verified email and member:accept")
        problem(api.call(other, 'POST', app + '/accept', wrong, 403), 'forbidden')
    problem(api.call(foreign, 'GET', app + '/activations/' + alice['id'], status=404), 'not_found')
    for tok, activation in zip(tokens, (alice, bob)):
        visible = {a['id'] for a in api.call(tok, 'GET', 'agents')['items']}
        if not set(activation['agents'].values()) <= visible:
            raise RuntimeError('assigned agent missing from member inventory')
    for name in personal:
        problem(api.call(tokens[1], 'GET', 'agents/' + alice['agents'][name], status=404), 'not_found')
    api.call(foreign, 'GET', 'agents/' + shared, status=404)
    api.call(backend, 'GET', 'agents/' + shared, status=403)
    timeout = config.get('timeout_seconds', 180)
    invocation_id = invoke_and_read(api, tokens[0], shared, 'MonApp acceptance', timeout)
    private_result = 'invocations/' + invocation_id + '/result'
    problem(api.call(tokens[1], 'GET', private_result, status=404), 'not_found')

    target = app + '/activations/' + alice['id']
    if sales_agent:
        for token in tokens:
            problem(api.call(token, 'GET', 'agents/' + sales_agent, status=404), 'not_found')
    event = {'version': 2, 'team_id': sales}
    key = str(uuid4())
    moved = api.call(backend, 'PUT', target, event, key=key)
    expected = {name: alice['agents'][name] for name in personal}
    if sales_agent:
        expected['sales'] = sales_agent
    for state in (moved, api.call(backend, 'PUT', target, event, key=key), api.call(backend, 'GET', target)):
        if (state['version'] != 2 or state['state'] != 'ready' or state['team_id'] != sales or
                state['principal_id'] != alice['principal_id'] or state['agents'] != expected):
            raise RuntimeError('team transfer did not preserve the requested activation and personal slots')
    alice_sessions = [tokens[0]]
    if members[0].get('keycloak_login'):
        alice_sessions.append(sign_in_again(config, members[0], tokens[0]))
    for token in alice_sessions:
        problem(api.call(token, 'GET', 'agents/' + shared, status=404), 'not_found')
        problem(api.call(token, 'POST', 'agents/' + shared + '/invocations',
                         {'content': [{'type': 'text', 'text': 'Removed Support access'}]}, 404), 'not_found')
        problem(api.call(token, 'GET', private_result, status=404), 'not_found')
        for agent in expected.values():
            api.call(token, 'GET', 'agents/' + agent)
    invoke_and_read(api, tokens[1], shared, 'Bob still belongs to Support', timeout)
    if sales_agent:
        problem(api.call(tokens[1], 'GET', 'agents/' + sales_agent, status=404), 'not_found')
        sales_id = invoke_and_read(api, alice_sessions[-1], sales_agent, 'Sales acceptance', timeout)
        problem(api.call(tokens[1], 'GET', 'invocations/' + sales_id + '/result', status=404), 'not_found')
    left = api.call(backend, 'PUT', target, {'version': 3, 'disabled': True})
    if members[0].get('keycloak_login'):
        alice_sessions.append(sign_in_again(config, members[0], alice_sessions[-1]))
    for token in alice_sessions:
        live_claims(token)
        problem(api.call(token, 'GET', 'agents', status=401), 'authentication_required')
    problem(api.call(alice_sessions[-1], 'POST', 'agents/' + expected['personal'] + '/invocations',
                     {'content': [{'type': 'text', 'text': 'After departure'}]}, 401), 'authentication_required')
    problem(api.call(backend, 'PUT', target, {'version': 2, 'team_id': team}, status=409), 'invalid_transition')
    final = api.call(backend, 'GET', target)
    if final['version'] != 3 or final['state'] != 'disabled':
        raise RuntimeError('stale transfer changed the departed activation')
    api.call(tokens[1], 'GET', 'agents/' + shared)
    audit = api.call(admin, 'GET', 'audit?limit=100')['items']
    if not any(e['action'] == 'application.member_updated' and e['target'] == alice['id'] for e in audit):
        raise RuntimeError('missing application offboarding audit record')
    problem(api.call(tokens[0], 'POST', app + '/accept', wrong, 403), 'forbidden')
    revoked = api.call(admin, 'POST', app + '/revoke', {})
    problem(api.call(backend, 'GET', target, status=401), 'authentication_required')
    if members[1].get('keycloak_login'):
        bob_new = sign_in_again(config, members[1], tokens[1])
        problem(api.call(bob_new, 'GET', 'agents', status=401), 'authentication_required')
    report = {
        'schema_version': 1, 'application_id': registration['id'], 'activations': [alice['id'], bob['id']],
        'personal_slots': {a['id']: {name: a['agents'][name] for name in personal} for a in (alice, bob)},
        'transfer': {'from_team_id': team, 'to_team_id': sales, 'version': moved['version'],
                     'agents': moved['agents'], 'revocations': moved.get('revocations', [])},
        'invocation_id': invocation_id, 'departure': left['state'], 'admitted_work': left['admitted_work'],
        'revocations': left.get('revocations', []),
        'application_revocations': revoked.get('revocations', []),
        'optional_checks': {'sales_agent': bool(sales_agent), 'fresh_member_sessions': bool(members[0].get('keycloak_login')),
                            'fresh_session_after_app_revoke': bool(members[1].get('keycloak_login')),
                            'pool_refusal': bool(config.get('refusal_pool_id')),
                            'wrong_audience': bool(config.get('wrong_audience_token_file')),
                            'reassigned_email': bool(config.get('reassigned_email_token_file'))},
    }
    report['revoked_check'] = verify_revoked(config, report)
    return report


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[2] == '--check-revoked':
        result = verify_revoked(json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[3]).read_text()))
    elif len(sys.argv) == 2:
        result = verify(json.loads(Path(sys.argv[1]).read_text()))
    else:
        raise SystemExit('usage: verify.py SCENARIO.json [--check-revoked REPORT.json]')
    print(json.dumps(result, indent=2))
