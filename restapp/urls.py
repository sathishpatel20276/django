from django.contrib import admin
from django.urls import path,include
from .views import CreateUserAPIView,authenticate_user,UserUpdateAPIView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/',CreateUserAPIView.as_view()),
    path('login/',authenticate_user),
    path('update/',UserUpdateAPIView.as_view()),
    
]
