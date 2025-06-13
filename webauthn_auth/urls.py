from django.urls import path
from . import views

urlpatterns = [
    path('register/challenge/', views.registration_challenge, name='registration-challenge'),
    path('register/verify/', views.registration_verification, name='registration-verify'),
    path('login/challenge/', views.authentication_challenge, name='authentication-challenge'),
    path('login/verify/', views.authentication_verification, name='authentication-verify'),
    path('profile/', views.user_profile, name='user-profile'),
    path('verify-token/', views.verify_sso_token_view, name='verify-sso-token'),
]