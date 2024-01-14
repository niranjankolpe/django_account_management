from email.message import EmailMessage
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from gfg import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from . tokens import *

import uuid

from authentication.models import *

# Create your views here.
def home(request):
    return render(request, 'authentication/index.html')

def signup(request):

    if request.method == "POST":
        username = request.POST.get("username")
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
        email = request.POST.get("email")
        pass1 = request.POST.get("pass1")
        pass2 = request.POST.get("pass2")

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists! Please try some other username")
            return redirect("home")
        
        if User.objects.filter(email=email):
            messages.error(request, "Email already registered! Please try some other email")
            return redirect("home")
        
        if len(username)>10:
            messages.error(request, "Username must be under 10 characters")
            return redirect("home")
        
        if pass1!=pass2:
            messages.error(request, "Passwords did not match!")
            return redirect("home")
        
        if not username.isalnum():
            messages.error(request, "Username must be alpha-numeric")
            return redirect("home")
        
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been created successfully! We also sent you a confirmation email. Please confirm your email in order to activate your account.")

        # Welcome Email
        subject = "Welcome to Django Login"
        message = "Hello " + myuser.first_name + "! \nWelcome to Django project\nThank you for visiting our website\nWe also sent you a confirmation email. Please confirm your email address in order to activate your account.\nThanking you\nTrial Django Admin"

        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        print("\n\nUser Detaills:\n1. Subject: {0}\n2. Message: {1}\n3. From Email: {2}\n4. To List: {3}\n\n".format(subject, message, from_email, to_list))
        send_mail(subject, message, from_email, to_list, fail_silently=False)
        
        # Email Address Confirmation
        current_site = get_current_site(request)
        email_subject = "Confirm your email @ GFG - Django Login"
        email_message = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        # email = EmailMessage(
        #     email_subject, email_message, settings.EMAIL_HOST_USER, [myuser.email] # type: ignore
        # )
        # email.fail_silently = False # type: ignore
        send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [myuser.email], fail_silently=False)
        # email.send() # type: ignore
        return redirect("signin")
    
    return render(request, 'authentication/signup.html')

def signin(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            fname = user.first_name # type: ignore
            data = {'fname': fname}
            # messages.add_message(request, messages.INFO, "Hello world.")
            messages.success(request, "Logged in successfully!")
            return render(request, 'authentication/index.html', data)
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('home')
    return render(request, 'authentication/signin.html')

def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("home")

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect("home")
    else:
        return render(request, "activation_failed.html")

def forgot_password(request):
    return render(request, "authentication/forgot_password.html")

def forgot_password_success(request):
    if request.method == "POST":
        username = request.POST.get("username")
        print("\n\nUsername: {0}\n\n".format(username))

        if not User.objects.filter(username=username):
            messages.error(request, "Username not found!")
            return redirect("home")
        
        user = User.objects.get(username=username)
        
        token = str(uuid.uuid4())
        send_forgot_password_mail(user.email, token)
        mod_obj = PasswordResetProfile(username=username, last_token=token, date=datetime.datetime.now())
        mod_obj.save()
        messages.success(request, "Password reset link sent to your email address!")
    return redirect("home")

def change_password(request, token):
    data = {'token': str(token)}
    return render(request, "authentication/change_password.html", data)

def reset_password(request):
    pass1 = request.POST.get("pass1")
    token = request.POST.get("token")
    profile = PasswordResetProfile.objects.get(last_token=token)
    username = profile.username
    print(f"\n\nGot this username: {username}")
    user_obj = User.objects.get(username=username)
    print(f"Got this user_obj: {user_obj}")
    print(f"Got this new password: {pass1}\n\n")
    user_obj.set_password(pass1)
    user_obj.save()

    messages.success(request, "Password reset successfully!")
    return redirect("home")