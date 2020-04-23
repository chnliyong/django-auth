import ssl
import json
import base64
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request

from jose import jwt
import certifi

from django.conf import settings


class Provider:
    def __init__(self, issuer):
        cnf = self._get_configuration(issuer)
        if cnf['issuer'] != issuer:
            raise ValueError('issuer not match')

        self.issuer = cnf['issuer']
        self.authorization_endpoint = cnf['authorization_endpoint']
        self.token_endpoint = cnf['token_endpoint']
        self.userinfo_endpoint = cnf['userinfo_endpoint']
        self.jwks_uri = cnf['jwks_uri']
        self.jwks = self._get_jwks(self.jwks_uri)


    @staticmethod
    def _get_configuration(issuer=None):
        if issuer is None:
            return None
        try:
            res = urlparse(issuer)
        except ValueError:
            raise
        else:
            if res == None:
                raise ValueError('Invalid issuer: ' + issuer)
            if res.scheme != 'https':
                raise ValueError('Issuer scheme should be https')

        discovery_url = issuer + '/.well-known/openid-configuration'
        resp = urlopen(discovery_url, timeout=5, context=ssl.create_default_context(cafile=certifi.where()))
        content = resp.read(4096)
        try:
            cnf = json.loads(content)
        except json.JSONDecodeError:
            cnf = None
            raise

        return cnf

    @staticmethod
    def _get_jwks(jwks_uri):
        resp = urlopen(jwks_uri, timeout=5, context=ssl.create_default_context(cafile=certifi.where()))
        content = resp.read(4096)
        try:
            jwks = json.loads(content)
        except json.JSONDecodeError:
            jwks = None
            raise

        return jwks




class Client:
    def __init__(self, issuer, client_id, client_secret, callback_url):
        self.provider = Provider(issuer)
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_url = callback_url


    def get_authn_url(self, state, **kwargs):
        response_type = kwargs['response_type'] if 'response_type' in kwargs else 'code'
        scope = kwargs['scope'] if 'scope' in kwargs else 'openid profile'
        query = {
            'response_type': response_type,
            'client_id': self.client_id,
            'scope': scope,
            'redirect_uri': self.callback_url,
            'state': state,
        }

        for k, v in kwargs:
            if k not in query:
                query[k] = v

        return self.provider.authorization_endpoint+'?'+urlencode(query)


    def get_token_request(self, code):
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'redirect_uri': self.callback_url,
            'code': code,
        }

        credential = base64.b64encode(':'.join((self.client_id, self.client_secret))
                                .encode('utf-8')).decode('utf-8')
        client_basic_auth = 'Basic ' + credential

        req = Request(self.provider.token_endpoint,
                      data = urlencode(data).encode('utf-8'),
                      headers={
                          'Authorization': client_basic_auth,
                          'Content-Type': 'application/x-www-form-urlencoded',
                      })

        return req


    def decode_jwt(self, token):
        return jwt.decode(token, self.provider.jwks, audience=self.client_id)


    def verify_id_token(self, id_token_jwt):
        id_token = self.decode_jwt(id_token_jwt)
        return id_token


    def get_userinfo_request(self, access_token):
        req = Request(self.provider.userinfo_endpoint,
                      headers={
                          'Authorization': 'Bearer '+access_token,
                      })
        return req


client = Client(settings.AUTHW_OIDC['ISSUER'],
                settings.AUTHW_OIDC['CLIENT_ID'],
                settings.AUTHW_OIDC['CLIENT_SECRET'],
                settings.AUTHW_OIDC['CALLBACK_URL'])
