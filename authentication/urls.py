from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('home', views.home),
    path('signup', views.signup, name="signup"),
    path('signin', views.signin, name="signin"),
    path('signout', views.signout, name="signout"), # type: ignore
    path('activate/<uidb64>/<token>', views.activate, name="activate"),
    path('forgot_password', views.forgot_password, name="forgot_password"),
    path('forgot_password_success', views.forgot_password_success, name="forgot_password_success"),
    path('change_password/<token>', views.change_password, name="change_password"),
    path('reset_password', views.reset_password, name="reset_password")
    
]
