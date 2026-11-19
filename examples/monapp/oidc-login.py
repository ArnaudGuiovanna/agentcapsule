#!/usr/bin/env python3
"""Exercise OIDC code/S256 in the bundled Keycloak realm using a test member."""
import argparse
import base64
import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.hidden = {}

    def handle_starttag(self, tag, attrs):
        props = dict(attrs)
        if tag == 'form' and props.get('id') == 'kc-form-login':
            self.action = props['action']
        if tag == 'input' and props.get('type') == 'hidden' and 'name' in props:
            self.hidden[props['name']] = props.get('value', '')


class Callback(Exception):
    pass


def origin(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or parts.username or not parts.hostname:
        raise ValueError('HTTPS URL required')
    return parts.hostname, parts.port or 443


class RealmRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, issuer, callback):
        self.issuer = issuer
        self.callback = callback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts._replace(query='', fragment='').geturl() == self.callback:
            raise Callback(urllib.parse.parse_qs(parts.query))
        if origin(newurl) != origin(self.issuer):
            raise ValueError('unexpected login redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def login(issuer, client_id, redirect_uri, username, password, tls):
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    browser = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=tls),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        RealmRedirects(issuer, redirect_uri))
    with browser.open(issuer + '/.well-known/openid-configuration', timeout=20) as response:
        config = json.load(response)
    if config['issuer'] != issuer or 'S256' not in config['code_challenge_methods_supported']:
        raise ValueError('unexpected provider metadata')
    for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        if origin(config[key]) != origin(issuer):
            raise ValueError('unexpected endpoint origin')

    params = dict(client_id=client_id, response_type='code', redirect_uri=redirect_uri, state=state,
                  scope='openid email member:accept member:invite org:read agent:read agent:invoke agent:content:read',
                  code_challenge=challenge, code_challenge_method='S256')
    form = LoginForm()
    with browser.open(config['authorization_endpoint'] + '?' + urllib.parse.urlencode(params), timeout=20) as page:
        form.feed(page.read().decode())
    if not form.action or origin(form.action) != origin(issuer):
        raise ValueError('expected the bundled Keycloak password form')
    data = urllib.parse.urlencode(dict(form.hidden, username=username, password=password)).encode()
    try:
        with browser.open(form.action, data, timeout=20):
            raise ValueError('test sign-in did not complete')
    except Callback as redirect:
        query = redirect.args[0]
    if query.get('state') != [state] or len(query.get('code', [])) != 1:
        raise ValueError('invalid authorization response')
    data = urllib.parse.urlencode(dict(grant_type='authorization_code', client_id=client_id,
                                       redirect_uri=redirect_uri, code=query['code'][0],
                                       code_verifier=verifier)).encode()
    with browser.open(config['token_endpoint'], data, timeout=20) as response:
        token = json.load(response)
    if token['token_type'].lower() != 'bearer':
        raise ValueError('unexpected credential type')
    return token['access_token']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('issuer', 'client-id', 'redirect-uri', 'username', 'password-file', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ca-file')
    args = parser.parse_args()
    source = Path(args.password_file)
    if os.name != 'nt' and source.stat().st_mode & 0o077:
        parser.error('password-file must be private')
    token = login(args.issuer, args.client_id, args.redirect_uri, args.username, source.read_text().strip(),
                  ssl.create_default_context(cafile=args.ca_file))
    with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
        out.write(token + '\n')


if __name__ == '__main__':
    main()
