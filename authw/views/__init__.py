from importlib import import_module

from django.shortcuts import render, redirect, resolve_url
from django.contrib.auth.decorators import login_required
from django.contrib import auth 

from authw.providers import provider_names

_view_modules = {
}


def _get_provider_view_module(provider):
    if provider is None or provider == '':
        raise ValueError('Empty provider argument.')

    if provider not in provider_names:
        raise ValueError('Provider {0} cannot be found'.format(provider))

    if provider not in _view_modules:
        try:
            _view_modules[provider] = import_module('.' + provider, __package__)
        except Exception:
            raise ImportError('Import view module for provider {0} failed'.format(provider))

    return _view_modules[provider]


def provider_login(request, provider):
    view_mod = _get_provider_view_module(provider)
    return view_mod.login(request)


def provider_callback(request, provider):
    view_mod = _get_provider_view_module(provider)
    return view_mod.callback(request)


@login_required
def account_profile(request):
    account = request.user
    return render(request, 'profile.html', context={'account': account})


def account_login(request):
    return render(request, 'login.html')


def account_logout(request):
    auth.logout(request)
    return redirect(resolve_url('account_login'))
