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
    print("=== WEBAUTHN VERIFY REGISTRATION ===")
    print("WEBAUTHN VERIFY PAYLOAD:", request.data)
    
    serializer = WebAuthnRegistrationResponseSerializer(data=request.data)
    if not serializer.is_valid():
        print("SERIALIZER ERRORS:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data['username']
    credential_id = serializer.validated_data['credential_id']
    
    print(f"Processing registration for username: {username}")
    print(f"Credential ID: {credential_id}")

    try:
        # Get temporary user and challenge
        temp_user = User.objects.get(username=f"temp_{username}", is_active=False)
        challenge_obj = RegistrationChallenge.objects.get(user=temp_user)
        
        print(f"Found temp user: {temp_user.username}")
        print(f"Found challenge: {challenge_obj.challenge}")

        # Prepare credential data for verification
        credential_data = {
            'id': credential_id,
            'rawId': credential_id,
            'response': {
                'attestationObject': serializer.validated_data['attestation_object'],
                'clientDataJSON': serializer.validated_data['client_data_json'],
            },
            'type': 'public-key',
        }
        
        print("Credential data prepared:")
        print(f"- id: {credential_data['id']}")
        print(f"- rawId: {credential_data['rawId']}")

        # Verify registration response
        print("Starting verification...")
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=base64url_decode(challenge_obj.challenge),
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
        )

        print(f"Verification completed successfully!")
        print(f"Verification object type: {type(verification)}")
        print(f"Verification attributes: {dir(verification)}")
        
        # The verification was successful if we get here without exception
        # VerifiedRegistration object contains the credential data we need
        print("✅ Registration verification successful")
        
        # Create actual user
        user = User.objects.create(
            username=username,
            email=temp_user.email,
            first_name=temp_user.first_name,
            last_name=temp_user.last_name,
            is_active=True,
        )
        
        print(f"Created user: {user.username}")

        # Store credential using data from VerifiedRegistration object
        WebAuthnCredential.objects.create(
            user=user,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        
        print("Stored WebAuthn credential")
        print(f"- credential_id length: {len(verification.credential_id)}")
        print(f"- public_key length: {len(verification.credential_public_key)}")
        print(f"- sign_count: {verification.sign_count}")

        # Clean up
        temp_user.delete()
        challenge_obj.delete()
        print("Cleaned up temp user and challenge")

        # Generate SSO token
        sso_token = generate_sso_token(user)
        
        response_data = {
            'verified': True,
            'success': True,  # Add this for compatibility
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'sso_token': sso_token,
        }
        
        print(f"Sending success response")
        return Response(response_data)

    except (User.DoesNotExist, RegistrationChallenge.DoesNotExist) as e:
        print(f"❌ User or challenge not found: {e}")
        return Response(
            {'error': 'Invalid registration attempt'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        print(f"❌ Registration failed with exception: {e}")
        print(f"Exception type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return Response(
            {'error': f'Registration failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def authentication_challenge(request):
    """Generate authentication challenge for WebAuthn login"""
    print("=== WEBAUTHN AUTHENTICATION CHALLENGE ===")
    print("Request data:", request.data)
    
    serializer = WebAuthnAuthenticationChallengeSerializer(data=request.data)
    if not serializer.is_valid():
        print("SERIALIZER ERRORS:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data.get('username')
    print(f"Generating challenge for username: {username}")

    # Get user credentials
    credentials = []
    user = None
    
    if username:
        try:
            user = User.objects.get(username=username)
            user_credentials = WebAuthnCredential.objects.filter(user=user)
            credentials = [PublicKeyCredentialDescriptor(id=cred.credential_id)
                          for cred in user_credentials]
            print(f"Found user: {user.username} with {len(credentials)} credentials")
        except User.DoesNotExist:
            print(f"User not found: {username}")
            return Response({'error': 'User not found'},
                          status=status.HTTP_404_NOT_FOUND)

    # Clean up old challenges (older than 5 minutes)
    old_challenges_deleted = AuthenticationChallenge.objects.filter(
        created_at__lt=datetime.now(timezone.utc) - timedelta(minutes=5)
    ).delete()
    print(f"Deleted {old_challenges_deleted[0]} old challenges")

    # Clean up any existing challenges for this user to prevent duplicates
    if user:
        existing_challenges_deleted = AuthenticationChallenge.objects.filter(user=user).delete()
        print(f"Deleted {existing_challenges_deleted[0]} existing challenges for user {user.username}")

    # Generate authentication options
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    print(f"Generated challenge: {base64url_encode(options.challenge)}")

    # Store new challenge
    challenge_obj = AuthenticationChallenge.objects.create(
        challenge=base64url_encode(options.challenge),
        user=user,
    )
    
    print(f"Stored challenge with ID: {challenge_obj.id}")

    response_data = {
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
    }
    
    print(f"Sending response: {response_data}")
    return Response(response_data)



@api_view(['POST'])
@permission_classes([AllowAny])
def authentication_verification(request):
    """Verify WebAuthn authentication response"""
    print("=== WEBAUTHN VERIFY AUTHENTICATION ===")
    print("AUTHENTICATION VERIFY PAYLOAD:", request.data)
    
    serializer = WebAuthnAuthenticationResponseSerializer(data=request.data)
    if not serializer.is_valid():
        print("SERIALIZER ERRORS:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    credential_id = serializer.validated_data['credential_id']
    print(f"Processing authentication for credential_id: {credential_id}")

    try:
        # Find credential and user
        # Note: credential_id from frontend is base64url, but stored credential_id might be bytes
        # Let's try to find it by decoding first
        try:
            credential_id_bytes = base64url_decode(credential_id)
            credential = WebAuthnCredential.objects.get(credential_id=credential_id_bytes)
        except WebAuthnCredential.DoesNotExist:
            # If not found with bytes, try with the string directly
            credential = WebAuthnCredential.objects.get(credential_id=credential_id)
        
        user = credential.user
        print(f"Found credential for user: {user.username}")

        # Get challenge
        challenge_obj = AuthenticationChallenge.objects.get(user=user)
        print(f"Found challenge: {challenge_obj.challenge}")

        # Prepare credential data for verification - SAME FORMAT AS REGISTRATION
        credential_data = {
            'id': credential_id,
            'rawId': credential_id,  # Keep as base64url string
            'response': {
                'authenticatorData': serializer.validated_data['authenticator_data'],
                'clientDataJSON': serializer.validated_data['client_data_json'],
                'signature': serializer.validated_data['signature'],
            },
            'type': 'public-key',
        }
        
        # Add userHandle if present
        if serializer.validated_data.get('user_handle'):
            credential_data['response']['userHandle'] = serializer.validated_data['user_handle']

        print("Credential data prepared:")
        print(f"- id: {credential_data['id']}")
        print(f"- rawId: {credential_data['rawId']}")
        print(f"- authenticatorData: {credential_data['response']['authenticatorData'][:50]}...")
        print(f"- clientDataJSON: {credential_data['response']['clientDataJSON'][:50]}...")
        print(f"- signature: {credential_data['response']['signature'][:50]}...")

        # Verify authentication response
        print("Starting authentication verification...")
        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=base64url_decode(challenge_obj.challenge),
            expected_origin=settings.WEBAUTHN_ORIGIN,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
        )

        print(f"Authentication verification completed successfully!")
        print(f"Verification object type: {type(verification)}")
        
        # Update sign count
        credential.sign_count = verification.new_sign_count
        credential.last_used = datetime.now(timezone.utc)
        credential.save()
        print(f"Updated credential sign count to: {verification.new_sign_count}")

        # Clean up challenge
        challenge_obj.delete()
        print("Cleaned up authentication challenge")

        # Generate SSO token
        sso_token = generate_sso_token(user)
        
        response_data = {
            'verified': True,
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'sso_token': sso_token,
        }
        
        print("✅ Authentication successful, sending response")
        return Response(response_data)

    except WebAuthnCredential.DoesNotExist:
        print("❌ Credential not found")
        return Response(
            {'error': 'Credential not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except AuthenticationChallenge.DoesNotExist:
        print("❌ Challenge not found")
        return Response(
            {'error': 'Challenge not found'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        print(f"❌ Authentication failed with exception: {e}")
        print(f"Exception type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
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
        
        

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User

import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
def clear_challenges(request):
    logger.info("=== CLEAR CHALLENGES ENDPOINT CALLED ===")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request data: {request.data}")
    
    username = request.data.get('username')
    logger.info(f"Extracted username: '{username}'")
    
    if not username:
        logger.warning("No username provided")
        return Response({'error': 'Username required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        logger.info(f"Attempting to clear challenges for user: {username}")
        
        # Look for both actual user and temporary user challenges
        deleted_count = 0
        
        # 1. Clear challenges for actual user (if exists)
        try:
            user = User.objects.get(username=username)
            actual_deleted, _ = RegistrationChallenge.objects.filter(user=user).delete()
            deleted_count += actual_deleted
            logger.info(f"Deleted {actual_deleted} challenges for actual user: {username}")
        except User.DoesNotExist:
            logger.info(f"No actual user found with username: {username}")
        
        # 2. Clear challenges for temporary user (temp_username)
        temp_username = f"temp_{username}"
        try:
            temp_user = User.objects.get(username=temp_username, is_active=False)
            temp_deleted, _ = RegistrationChallenge.objects.filter(user=temp_user).delete()
            deleted_count += temp_deleted
            logger.info(f"Deleted {temp_deleted} challenges for temp user: {temp_username}")
            
            # Also delete the temporary user if no challenges remain
            if temp_deleted > 0:
                temp_user.delete()
                logger.info(f"Deleted temporary user: {temp_username}")
                
        except User.DoesNotExist:
            logger.info(f"No temp user found with username: {temp_username}")
        
        # 3. Also clear any orphaned challenges (fallback)
        orphaned_deleted, _ = RegistrationChallenge.objects.filter(
            created_at__lt=datetime.now(timezone.utc) - timedelta(minutes=5)
        ).delete()
        deleted_count += orphaned_deleted
        logger.info(f"Deleted {orphaned_deleted} orphaned challenges")
        
        response_data = {
            'success': True,
            'deleted_count': deleted_count,
            'message': f'Cleared {deleted_count} challenges for user {username}'
        }
        
        logger.info(f"Sending response: {response_data}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"Error in clear_challenges: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
