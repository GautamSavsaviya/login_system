from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.conf import settings
from .tokens import generattoken

# Create your views here.


def index(request):
    return render(request, 'authentication/index.html')


def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if username == "":
            messages.error(request, 'Username must be enter...!')
            return render(request, 'authentication/signup.html')

        if User.objects.filter(username=username):
            messages.error(
                request, 'Username is already exist. please, enter different username...!')
            return render(request, 'authentication/signup.html')

        # if User.objects.filter(email=email):
        #     messages.error(
        #         request, 'Email is already exist. please, enter different email...!')
        #     return render(request, 'authentication/signup.html')

        
        
        if not username.isalnum:
            messages.error(request, 'Username must be alpha-numeric...!')
            return render(request, 'authentication/signup.html')

        if pass1 != pass2:
            messages.error(request, 'Password does not match..!')
            return render(request, 'authentication/signup.html')

        user = User.objects.create_user(username, email, pass1)
        user.first_name = fname
        user.last_name = lname
        user.is_active = False
        user.save()
        messages.success(request, "You are register successfully...! We send you a confirmation mail to validate you email id")


        # Welcom mail
        subject = "Welcome email"
        message = f"Hello {fname}!!\n Welcome to out website!\nThank you for visiting our website.\n We have also send you a confirmation mail. Please confirm your email in order to active your accout. \n\nThanking you\nAdmin"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        send_mail(subject, message, from_email,
                  recipient_list, fail_silently=True)
        


        # Email varifation mail
        current_site = get_current_site(request)
        subject = "Confirmation mail"
        message = render_to_string('email-confirmation.html',{
            'name':user.first_name,
            'domain':current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generattoken.make_token(user),
        })
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=True,
        )

        return redirect('login')
    return render(request, 'authentication/signup.html')


def signin(request):
    if request.method == "POST":
        username = request.POST["username"]
        pass1 = request.POST["pass1"]

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            messages.success(request, 'You are successfully logged in...!')

            return redirect('index')
        else:
            messages.error(request, 'Username or password does not exist...!')
            return redirect('login')
    return render(request, 'authentication/login.html')


def signout(request):
    logout(request)
    messages.success(request, 'You are successfully logged out...!')

    return redirect('index')


def activate(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and generattoken.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return redirect('index')
    else:
        return render(request, 'activation-faild.html')