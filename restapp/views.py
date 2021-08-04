from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from restapp.serializers import UserSerializer,UpdataUserSerializer

# from rest_framework.generics import RetrieveUpdateAPIView

from rest_framework.decorators import api_view,permission_classes
from .models import User
# Create your views here.
from django.conf import settings
from rest_framework.settings import api_settings
from rest_framework_jwt.settings import api_settings

from django.contrib.auth.signals import user_logged_in

from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_text
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token,password_reset_token
import six
from django.db.models.query_utils import Q
from django.contrib.auth.hashers import make_password

import logging
logger = logging.getLogger('django')

import jwt
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

class CreateUserAPIView(APIView):
    # Allow any user (authenticated or not) to access this url 
    permission_classes = (AllowAny,)

    def post(self, request):
        user = request.data
        email = user.get("email")
        password1 = user.get("password")

        print(email)
        serializer = UserSerializer(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        try:
            user = User(email=email,
            password =password1)
            user.password = make_password(password1)
            user.is_active = False
            user.save()
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            link=reverse(
                'activate',kwargs={
                'uidb64':uidb64, 'token':account_activation_token.make_token(user)
                }
                )
            mail_subject = 'Activate your blog account.'
            activate_url= 'http://'+domain+link
            message = 'Hi ' + user.username + 'Please use this link \
            to verify your account\n' + activate_url
            to_email = email
            email = EmailMessage(
                        mail_subject, message, to=[to_email]
            )
            email.send(fail_silently=False)
            
            data = 'Please confirm your email address to complete the registration'
            logger.info('Please confirm your email address to complete the registration')
            return Response(data,status=201)
        except Exception as error:
            user.delete()
            serializer.delete()
            data = 'something went wrong unable to send a mail: {error}'
            logger.critical('something went wrong unable to send a mail:\n %s',error)
            return Response(data,status=201)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny, ])
def authenticate_user(request):
 
    try:
        email = request.data['email']
        password = request.data['password']

        user = User.objects.get(email=email, password=password)
        # print(user)
        userf = User.objects.get(email=email)
        # print(userf)
        if user:
            try:
                payload = jwt_payload_handler(user)
                token = jwt.encode(payload, settings.SECRET_KEY)
                user_details = {}
                user_details['name'] = "%s %s" % (
                    user.first_name, user.last_name)
                user_details['email']= user.email
                user_details['token'] = token
                user_logged_in.send(sender=user.__class__,
                                    request=request, user=user)
                return Response(user_details, status=status.HTTP_200_OK)
 
            except Exception as e:
                raise e
        else:
            res = {
                'error': 'can not authenticate with the given credentials or the account has been deactivated'}
            return Response(res, status=status.HTTP_403_FORBIDDEN)
    except:
        res = {'error': 'please provide a valid email and a password'}
        return Response(res)

class UserUpdateAPIView(APIView):
 
    # Allow only authenticated users to access this url
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdataUserSerializer
 
    # def get(self, request, *args, **kwargs):
    #     # serializer to handle turning our `User` object into something that
    #     # can be JSONified and sent to the client.
    #     serializer = self.serializer_class(request.user)
 
    #     return Response(serializer.data, status=status.HTTP_200_OK)
 
    def put(self, request, *args, **kwargs):
        serializer_data = request.data
        print(serializer_data)
 
        serializer = UpdataUserSerializer(
            request.user, data=serializer_data, partial=True
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

 
        return Response(serializer.data, status=status.HTTP_200_OK)