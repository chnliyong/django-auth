from django.urls import path
from authw import views


urlpatterns = [
    path('login', views.account_login, name='account_login'),
    path('logout', views.account_logout, name='account_logout'),
    path('profile', views.account_profile, name='account_profile'),
    path('<provider>/login', views.provider_login, name='provider_login'),
    path('<provider>/callback', views.provider_callback, name='provider_callback'),
]
