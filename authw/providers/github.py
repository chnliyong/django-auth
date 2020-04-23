import ssl
import json
import base64
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request

from jose import jwt
import certifi

from django.conf import settings


class Provider:
    def __init__(self):
        self.authorization_endpoint = 'https://github.com/login/oauth/authorize'
        self.token_endpoint = 'https://github.com/login/oauth/access_token'
        self.userinfo_endpoint = 'https://api.github.com/user'


class Client:
    def __init__(self, client_id, client_secret, callback_url):
        self.provider = Provider()
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_url = callback_url

    def get_authn_url(self, state, **kwargs):
        scope = kwargs['scope'] if 'scope' in kwargs else 'read:user'
        query = {
            'client_id': self.client_id,
            'scope': scope,
            'redirect_uri': self.callback_url,
            'state': state,
        }

        for k, v in kwargs:
            if k not in query:
                query[k] = v

        return self.provider.authorization_endpoint+'?'+urlencode(query)

    def get_token_request(self, code, state):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.callback_url,
            'code': code,
            'state': state,
        }

        req = Request(self.provider.token_endpoint,
                      data = urlencode(data).encode('utf-8'),
                      headers={
                          'Content-Type': 'application/x-www-form-urlencoded',
                          'Accept': 'application/json',
                      })

        return req


    def get_userinfo_request(self, access_token):
        req = Request(self.provider.userinfo_endpoint,
                      headers={
                          'Authorization': 'token '+access_token,
                          'Accept': 'application/json',
                      })
        return req


client = Client(settings.AUTHW_GITHUB['CLIENT_ID'],
                settings.AUTHW_GITHUB['CLIENT_SECRET'],
                settings.AUTHW_GITHUB['CALLBACK_URL'])
