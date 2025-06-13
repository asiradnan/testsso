from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from .utils import verify_sso_token

class WebAuthnAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        user_data = verify_sso_token(token)
        
        if not user_data:
            raise AuthenticationFailed('Invalid or expired token')

        try:
            user = User.objects.get(id=user_data['user_id'])
            return (user, None)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')