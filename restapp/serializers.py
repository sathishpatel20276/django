from rest_framework import serializers
from.models import User
 
 
class UserSerializer(serializers.ModelSerializer):

 
    class Meta(object):
        model = User
        fields = ( 'email', 'first_name', 'last_name',
                   'password')
        extra_kwargs = {'password': {'write_only': True}}

class UpdataUserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User
        fields = ('first_name', 'last_name')
        # extra_kwargs = {'password': {'write_only': True}}

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.save()
        return instance