#!/usr/bin/env python3
"""Run the two-member MonApp HTTP conformance journey in a disposable tenant."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import ssl
import sys
import time
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
    perms = ['read_metadata', 'invoke', 'read_content']
    plan = api.call(admin, 'POST', 'assignment-policies/plan', {
        'application_id': registration['id'], 'on_exhaustion': 'refuse', 'allowed_teams': [team],
        'slots': [{'name': 'personal', 'pool_id': config['pool_id'], 'permissions': perms},
                  {'name': 'support', 'team_id': team, 'agent_id': shared, 'permissions': perms}]}, 201)
    api.call(admin, 'POST', f'assignment-policies/{plan["id"]}/apply', {})
    invitations = [api.call(admin, 'POST', app + '/invitations', {
        'policy_id': plan['id'], 'team_id': team, 'email': m['email'],
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}, 201) for m in members]
    api.call(tokens[1], 'POST', app + '/accept', {'proof': invitations[0]['proof']}, 404)

    def accept(i):
        data = {'proof': invitations[i]['proof']}
        key = str(uuid4())
        first = api.call(tokens[i], 'POST', app + '/accept', data, key=key)
        if api.call(tokens[i], 'POST', app + '/accept', data, key=key)['id'] != first['id']:
            raise RuntimeError('acceptance replay allocated a second activation')
        return api.wait(backend, app + '/activations/' + first['id'], 'ready',
                        ('waiting_capacity', 'preparing'), config.get('timeout_seconds', 180))

    with ThreadPoolExecutor(max_workers=2) as workers:
        alice, bob = workers.map(accept, range(2))
    if alice['agents']['personal'] == bob['agents']['personal'] or any(
            a['agents']['support'] != shared for a in (alice, bob)):
        raise RuntimeError('incorrect personal/shared allocation')
    for tok, activation in zip(tokens, (alice, bob)):
        visible = {a['id'] for a in api.call(tok, 'GET', 'agents')['items']}
        if not set(activation['agents'].values()) <= visible:
            raise RuntimeError('assigned agent missing from member inventory')
    api.call(tokens[1], 'GET', 'agents/' + alice['agents']['personal'], status=404)
    api.call(foreign, 'GET', 'agents/' + shared, status=404)
    api.call(backend, 'GET', 'agents/' + shared, status=403)
    result = api.call(tokens[0], 'POST', 'agents/' + shared + '/invocations',
                      {'content': [{'type': 'text', 'text': 'MonApp acceptance'}]}, 202)
    invocation = 'invocations/' + result['id']
    api.wait(tokens[0], invocation, 'completed', ('accepted', 'scheduled', 'working'),
             config.get('timeout_seconds', 180))
    api.call(tokens[0], 'GET', invocation + '/result')
    api.call(tokens[1], 'GET', invocation + '/result', status=404)

    target = app + '/activations/' + alice['id']
    api.call(backend, 'PUT', target, {'version': 2})
    api.call(tokens[0], 'GET', 'agents/' + shared, status=404)
    api.call(tokens[0], 'GET', 'agents/' + alice['agents']['personal'])
    left = api.call(backend, 'PUT', target, {'version': 3, 'disabled': True})
    api.call(backend, 'PUT', target, {'version': 2, 'team_id': team}, status=409)
    api.call(tokens[0], 'GET', 'agents', status=401)
    audit = api.call(admin, 'GET', 'audit?limit=100')['items']
    if not any(e['action'] == 'application.member_updated' and e['target'] == alice['id'] for e in audit):
        raise RuntimeError('missing application offboarding audit record')
    api.call(admin, 'POST', app + '/revoke', {})
    api.call(tokens[1], 'GET', 'agents', status=401)
    return {'schema_version': 1, 'application_id': registration['id'], 'activations': [alice['id'], bob['id']],
            'invocation_id': result['id'], 'departure': left['state'], 'revocations': left.get('revocations', [])}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify.py <scenario.json>')
    print(json.dumps(verify(json.loads(Path(sys.argv[1]).read_text())), indent=2))
