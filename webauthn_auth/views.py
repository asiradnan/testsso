import base64
import json
from datetime import datetime, timezone, timedelta
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
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

from .models import WebAuthnCredential, RegistrationChallenge, AuthenticationChallenge, SSOToken
from .serializers import *
from .utils import generate_sso_token, base64url_decode, base64url_encode

@api_view(['POST'])
@permission_classes([AllowAny])
def registration_challenge(request):
    """Generate registration challenge for WebAuthn registration"""
    serializer = WebAuthnRegistrationChallengeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data['username']
    
    # Check if user already exists
    if User.objects.filter(username=username).exists():
        return Response(
            {'error': 'User already exists'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    # Generate registration options
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=username.encode('utf-8'),
        user_name=username,
        user_display_name=serializer.validated_data.get('first_name', username),
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Store challenge temporarily (clean up old challenges)
    RegistrationChallenge.objects.filter(
        created_at__lt=datetime.now(timezone.utc) - timedelta(minutes=5)
    ).delete()

    # Create temporary user for challenge storage
    temp_user, created = User.objects.get_or_create(
        username=f"temp_{username}",
        defaults={
            'email': serializer.validated_data.get('email', ''),
            'first_name': serializer.validated_data.get('first_name', ''),
            'last_name': serializer.validated_data.get('last_name', ''),
            'is_active': False,
        }
    )

    RegistrationChallenge.objects.create(
        user=temp_user,
        challenge=base64url_encode(options.challenge)
    )

    return Response({
        'challenge': base64url_encode(options.challenge),
        'rp': {'id': options.rp.id, 'name': options.rp.name},
        'user': {
            'id': base64url_encode(options.user.id),
            'name': options.user.name,
            'displayName': options.user.display_name,
        },
        'pubKeyCredParams': [
    {'type': 'public-key', 'alg': param.alg}
    for param in options.pub_key_cred_params
],

        'timeout': options.timeout,
        'authenticatorSelection': {
            'authenticatorAttachment': options.authenticator_selection.authenticator_attachment.value,
            'residentKey': options.authenticator_selection.resident_key.value,
            'userVerification': options.authenticator_selection.user_verification.value,
        },
        'attestation': options.attestation.value,
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def registration_verification(request):
    """Verify WebAuthn registration response"""
    serializer = WebAuthnRegistrationResponseSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data['username']
    
    try:
        # Get temporary user and challenge
        temp_user = User.objects.get(username=f"temp_{username}", is_active=False)
        challenge_obj = RegistrationChallenge.objects.get(user=temp_user)
        
        # Verify registration response
        verification = verify_registration_response(
            credential={
                'id': serializer.validated_data['credential_id'],
                'rawId': base64url_decode(serializer.validated_data['credential_id']),
                'response': {
                    'attestationObject': base64url_decode(serializer.validated_data['attestation_object']),
                    'clientDataJSON': base64url_decode(serializer.validated_data['client_data_json']),
                },
                'type': 'public-key',
            },
            expected_challenge=base64url_decode(challenge_obj.challenge),
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
        )

        if verification.verified:
            # Create actual user
            user = User.objects.create(
                username=username,
                email=temp_user.email,
                first_name=temp_user.first_name,
                last_name=temp_user.last_name,
                is_active=True,
            )

            # Store credential
            WebAuthnCredential.objects.create(
                user=user,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
            )

            # Clean up
            temp_user.delete()
            challenge_obj.delete()

            # Generate SSO token
            sso_token = generate_sso_token(user)

            return Response({
                'verified': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                },
                'sso_token': sso_token,
            })
        else:
            return Response(
                {'error': 'Registration verification failed'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    except (User.DoesNotExist, RegistrationChallenge.DoesNotExist):
        return Response(
            {'error': 'Invalid registration attempt'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': f'Registration failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def authentication_challenge(request):
    """Generate authentication challenge for WebAuthn login"""
    serializer = WebAuthnAuthenticationChallengeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data.get('username')
    
    # Get user credentials
    credentials = []
    user = None
    
    if username:
        try:
            user = User.objects.get(username=username)
            user_credentials = WebAuthnCredential.objects.filter(user=user)
            credentials = [
                PublicKeyCredentialDescriptor(id=cred.credential_id)
                for cred in user_credentials
            ]
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

    # Generate authentication options
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # Store challenge
    AuthenticationChallenge.objects.filter(
        created_at__lt=datetime.now(timezone.utc) - timedelta(minutes=5)
    ).delete()

    AuthenticationChallenge.objects.create(
        challenge=base64url_encode(options.challenge),
        user=user,
    )

    return Response({
        'challenge': base64url_encode(options.challenge),
        'timeout': options.timeout,
        'rpId': options.rp_id,
        'allowCredentials': [
            {
                'type': 'public-key',
                'id': base64url_encode(cred.id),
            }
            for cred in options.allow_credentials
        ] if options.allow_credentials else [],
        'userVerification': options.user_verification.value,
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def authentication_verification(request):
    """Verify WebAuthn authentication response"""
    serializer = WebAuthnAuthenticationResponseSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    credential_id = base64url_decode(serializer.validated_data['credential_id'])
    
    try:
        # Find credential and user
        credential = WebAuthnCredential.objects.get(credential_id=credential_id)
        user = credential.user

        # Get challenge
        challenge_obj = AuthenticationChallenge.objects.get(user=user)

        # Verify authentication response
        verification = verify_authentication_response(
            credential={
                'id': serializer.validated_data['credential_id'],
                'rawId': credential_id,
                'response': {
                    'authenticatorData': base64url_decode(serializer.validated_data['authenticator_data']),
                    'clientDataJSON': base64url_decode(serializer.validated_data['client_data_json']),
                    'signature': base64url_decode(serializer.validated_data['signature']),
                },
                'type': 'public-key',
            },
            expected_challenge=base64url_decode(challenge_obj.challenge),
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
        )

        if verification.verified:
            # Update sign count
            credential.sign_count = verification.new_sign_count
            credential.save()

            # Clean up challenge
            challenge_obj.delete()

            # Generate SSO token
            sso_token = generate_sso_token(user)

            return Response({
                'verified': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                },
                'sso_token': sso_token,
            })
        else:
            return Response(
                {'error': 'Authentication verification failed'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    except WebAuthnCredential.DoesNotExist:
        return Response(
            {'error': 'Credential not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except AuthenticationChallenge.DoesNotExist:
        return Response(
            {'error': 'Challenge not found'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': f'Authentication failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
def user_profile(request):
    """Get authenticated user profile"""
    return Response({
        'id': request.user.id,
        'username': request.user.username,
        'email': request.user.email,
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
        'credentials': [
            {
                'id': base64url_encode(cred.credential_id),
                'name': cred.name,
                'created_at': cred.created_at,
                'last_used': cred.last_used,
            }
            for cred in request.user.webauthn_credentials.all()
        ]
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_sso_token_view(request):
    """Verify SSO token for other applications"""
    token = request.data.get('token')
    if not token:
        return Response(
            {'error': 'Token required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    from .utils import verify_sso_token
    user_data = verify_sso_token(token)
    
    if user_data:
        return Response({
            'valid': True,
            'user': {
                'id': user_data['user_id'],
                'username': user_data['username'],
                'email': user_data['email'],
            }
        })
    else:
        return Response({
            'valid': False,
            'error': 'Invalid or expired token'
        }, status=status.HTTP_401_UNAUTHORIZED)