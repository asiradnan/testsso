from rest_framework import serializers
from django.contrib.auth.models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

class WebAuthnRegistrationChallengeSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

class WebAuthnRegistrationResponseSerializer(serializers.Serializer):
    credential_id = serializers.CharField()
    public_key = serializers.CharField()
    attestation_object = serializers.CharField()
    client_data_json = serializers.CharField()
    username = serializers.CharField()

class WebAuthnAuthenticationChallengeSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)

class WebAuthnAuthenticationResponseSerializer(serializers.Serializer):
    credential_id = serializers.CharField()
    authenticator_data = serializers.CharField()
    client_data_json = serializers.CharField()
    signature = serializers.CharField()
    user_handle = serializers.CharField(required=False)