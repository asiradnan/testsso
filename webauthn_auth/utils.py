import base64
import json
import jwt
from datetime import datetime, timezone
from django.conf import settings
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

def generate_sso_token(user):
    """Generate SSO token for authenticated user"""
    payload = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'exp': datetime.now(timezone.utc) + settings.SSO_TOKEN_EXPIRY,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SSO_SECRET_KEY, algorithm='HS256')

def verify_sso_token(token):
    """Verify SSO token and return user data"""
    try:
        payload = jwt.decode(token, settings.SSO_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def base64url_decode(data):
    """Decode base64url string"""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def base64url_encode(data):
    """Encode to base64url string"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')