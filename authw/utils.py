from django.utils.crypto import get_random_string
from django.shortcuts import resolve_url
from django.contrib import auth
from django.conf import settings

def generate_state():
    return get_random_string(16)


def get_redirect_url(request):
    redirect_to = request.POST.get(auth.REDIRECT_FIELD_NAME, 
            request.GET.get(auth.REDIRECT_FIELD_NAME, ''))
    return redirect_to or resolve_url(settings.LOGIN_REDIRECT_URL) 
