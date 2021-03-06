import json
import ssl
from urllib import request as urllib_request

from django.shortcuts import render
from django.contrib import auth
from django.shortcuts import resolve_url
from django.http import HttpResponseRedirect, JsonResponse, HttpResponseBadRequest
from django.conf import settings

import certifi

from authw.providers import github
from authw import utils


def login(request):
    redirect_to = utils.get_redirect_url(request)
    if request.user.is_authenticated:
        return HttpResponseRedirect(redirect_to)

    state = utils.generate_state()
    authn_url = github.client.get_authn_url(state)

    # Save state value for lately verify in callback request
    request.session['github.state'] = state
    request.session['login.redirect_to'] = redirect_to

    return HttpResponseRedirect(authn_url)


def callback(request):
    state = request.GET.get('state', '')
    code = request.GET.get('code', '')

    if state == '' or code == '':
        return HttpResponseBadRequest(b'state and code required')

    orig_state = request.session['github.state']
    if state != orig_state:
        return HttpResponseBadRequest(b'state not match')

    token_req = github.client.get_token_request(code, state)

    resp = urllib_request.urlopen(token_req, timeout=5, context=ssl.create_default_context(cafile=certifi.where()))
    content = resp.read(4096)

    res = json.loads(content)

    try:
        access_token = res['access_token']
    except KeyError:
        raise

    userinfo_req = github.client.get_userinfo_request(access_token)
    resp = urllib_request.urlopen(userinfo_req, timeout=5, context=ssl.create_default_context(cafile=certifi.where()))
    content = resp.read(4096)
    userinfo = json.loads(content)
    print(userinfo)

    username = userinfo['login']
    email = userinfo['email']

    user_model = auth.get_user_model()
    try:
        user = user_model.objects.get(username=username)
        # update user info
        if user.email != email:
            user.email = email
            user.save()
    except user_model.DoesNotExist:
        user = user_model.objects.create_user(username, email)

    # set signed in state
    auth.login(request, user)

    redirect_to = request.session['login.redirect_to']

    return HttpResponseRedirect(redirect_to)
