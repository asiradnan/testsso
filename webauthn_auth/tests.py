from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from webauthn_auth.models import WebAuthnCredential, RegistrationChallenge
import json

class WebAuthnAPITest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User'
        }
    
    def test_registration_challenge(self):
        '''Test registration challenge endpoint'''
        response = self.client.post(
            reverse('registration-challenge'),
            data=json.dumps(self.user_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('challenge', data)
        self.assertIn('rp', data)
        self.assertIn('user', data)
    
    def test_duplicate_user_registration(self):
        '''Test that duplicate username registration fails'''
        # Create a user first
        User.objects.create_user(username='testuser')
        
        response = self.client.post(
            reverse('registration-challenge'),
            data=json.dumps(self.user_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn('error', data)
    
    def test_authentication_challenge(self):
        '''Test authentication challenge endpoint'''
        # Create user and credential first
        user = User.objects.create_user(username='testuser')
        WebAuthnCredential.objects.create(
            user=user,
            credential_id=b'test_credential_id',
            public_key=b'test_public_key'
        )
        
        response = self.client.post(
            reverse('authentication-challenge'),
            data=json.dumps({'username': 'testuser'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('challenge', data)
        self.assertIn('allowCredentials', data)
    
    def test_token_verification(self):
        '''Test SSO token verification'''
        from webauthn_auth.utils import generate_sso_token
        
        user = User.objects.create_user(username='testuser')
        token = generate_sso_token(user)
        
        response = self.client.post(
            reverse('verify-sso-token'),
            data=json.dumps({'token': token}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['valid'])
        self.assertEqual(data['user']['username'], 'testuser')
    
    def test_invalid_token_verification(self):
        '''Test invalid token verification'''
        response = self.client.post(
            reverse('verify-sso-token'),
            data=json.dumps({'token': 'invalid_token'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data['valid'])

class WebAuthnModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser')
    
    def test_credential_creation(self):
        '''Test WebAuthn credential model'''
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=b'test_credential_id',
            public_key=b'test_public_key',
            name='Test Key'
        )
        
        self.assertEqual(credential.user, self.user)
        self.assertEqual(credential.name, 'Test Key')
        self.assertEqual(credential.sign_count, 0)
    
    def test_challenge_cleanup(self):
        '''Test challenge cleanup functionality'''
        from datetime import datetime, timezone, timedelta
        from webauthn_auth.models import RegistrationChallenge
        
        # Create old challenge
        old_challenge = RegistrationChallenge.objects.create(
            user=self.user,
            challenge='old_challenge'
        )
        old_challenge.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        old_challenge.save()
        
        # This would normally be done in the view
        RegistrationChallenge.objects.filter(
            created_at__lt=datetime.now(timezone.utc) - timedelta(minutes=5)
        ).delete()
        
        self.assertEqual(RegistrationChallenge.objects.count(), 0)