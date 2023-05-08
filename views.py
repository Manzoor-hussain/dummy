from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.middleware.csrf import get_token

from core.utils import get_company_session_info
from superadmin.models import DemateProfile, UserProfile, Company
from superadmin.serializers import DemateProfileSerializer, CompanySerializer, UserSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMessage
import os
import pdb




from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes



@login_required
def get_index_page(request):
    company_img, company_name = get_company_session_info()
    active_users = User.objects.filter(is_active=True).exclude(is_superuser=True).count()
    active_demates = DemateProfile.objects.filter(status=True).count()
    response = render(request, 'superadmin/index.html', context={'demates': active_demates, 'users': active_users})
    response.set_cookie(key='company_img', value=company_img)
    response.set_cookie(key='company_name', value=company_name)
    return response


def login_page(request):
    company_img, company_name = get_company_session_info()

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user_ = authenticate(username=username, password=password)
        if user_:
            login(request, user_)

            if user_.is_superuser:
                response = redirect('superadmin:dashboard')
            else:
                response = redirect('core:dashboard')
            response.set_cookie(key='name', value=user_.first_name)
            response.set_cookie(key='email', value=user_.username)
            profile, _ = UserProfile.objects.get_or_create(user=user_)
            img = profile.image
            if not img:
                img = '/static/wheel.gif'
            response.set_cookie(key='image', value=img)
            response.set_cookie(key='company_img', value=company_img)
            response.set_cookie(key='company_name', value=company_name)
            return response

    response = render(request, 'superadmin/auth/login.html')
    response.set_cookie(key='company_img', value=company_img)
    response.set_cookie(key='company_name', value=company_name)
    return response


def register_page(request):
    company_img, company_name = get_company_session_info()

    if request.method == 'POST':
        name_ = request.POST['full_name']
        email = request.POST['email'].lower().strip()
        password = request.POST['password']
        mobile = request.POST['mobile'].lower().strip()

        if User.objects.filter(username=email).exists():
            return JsonResponse(status=400, data={'error': 'This email address already registered'})

        if UserProfile.objects.filter(mobile=mobile).exists():
            return JsonResponse(status=400, data={'error': 'This phone number already registered'})
        uu = User.objects.create(first_name=name_, email=email, username=email)
        uu.set_password(password)
        uu.save()

        UserProfile.objects.create(user=uu, mobile=mobile)
        return JsonResponse(status=200, data={})

    response = render(request, 'superadmin/auth/register.html')
    response.set_cookie(key='company_img', value=company_img)
    response.set_cookie(key='company_name', value=company_name)
    return response


@login_required
def logout_page(request):
    logout(request)
    return redirect('/login')


@login_required
def demate_profile(request):
    demates = DemateProfile.objects.all()
    return render(request, 'superadmin/demate.html', context={'demates': demates})


@api_view(['POST'])
@login_required
def add_demate_profile(request):
    id_ = request.GET.get('id', None)
    data_ = request.data

    if id_:
        dd = DemateProfile.objects.get(id=id_)
        if 'image' in request.FILES:
            dd.image = request.FILES['image']
        if 'setup_file' in request.FILES:
            dd.setup_file = request.FILES['setup_file']
        dd.title = data_['title']
        dd.token_time = data_['token_time']
        dd.notification_hours = data_['notification_hours']
        dd.sort = data_['sort']
        dd.setup_details = data_['setup_details']
        dd.package_id = data_['package_id']
        dd.save()
    else:
        data_serializer = DemateProfileSerializer(data=data_)
        if data_serializer.is_valid():
            data_serializer.save()
    return Response(status=200)


@api_view(['POST'])
@login_required
def delete_demate_profiles(request):
    DemateProfile.objects.filter(id=request.data['id']).delete()
    return Response(status=200)


@api_view(['GET'])
@login_required
def get_demate_profile(request):
    profile_ = DemateProfile.objects.get(id=request.GET.get('id'))
    data_ = DemateProfileSerializer(profile_)
    data_ = data_.data
    return Response(status=200, data=data_)


@api_view(['POST'])
@login_required
def change_demate_profile(request):
    dm_ = DemateProfile.objects.get(id=request.POST['id'])
    status_ = True
    if dm_.status:
        status_ = False
    dm_.status = status_
    dm_.save()
    return Response(status=200)


@login_required
def users_page(request):
    users = User.objects.filter(is_superuser=False)
    return render(request, 'superadmin/users.html', context={'users': users})


@api_view(['POST'])
@login_required
def delete_user(request):
    User.objects.filter(id=request.data['id']).delete()
    return Response(status=200)


@api_view(['POST'])
@login_required
def change_user(request):
    dm_ = User.objects.get(id=request.POST['id'])
    status_ = True
    if dm_.is_active:
        status_ = False
    dm_.is_active = status_
    dm_.save()
    return Response(status=200)


@api_view(['GET'])
@login_required
def get_user_profile(request):
    user_ = User.objects.get(id=request.GET.get('id'))
    data_ = UserSerializer(user_)
    data_ = data_.data
    up_, _ = UserProfile.objects.get_or_create(user=user_)
    data_['mobile'] = up_.mobile
    return Response(status=200, data=data_)


@api_view(['POST'])
@login_required
def add_user(request):
    id_ = request.GET.get('id', None)
    data_ = request.data
    name_ = request.POST['full_name']
    email = request.POST['email'].lower().strip()
    password = request.POST['password']
    mobile = request.POST['mobile'].lower().strip()

    if not id_:
        if User.objects.filter(username=email).exists():
            return JsonResponse(status=400, data={'error': 'This email address already registered'})

        if UserProfile.objects.filter(mobile=email).exists():
            return JsonResponse(status=400, data={'error': 'This phone number already registered'})

        uu = User.objects.create(first_name=name_, email=email, username=email)
        uu.set_password(password)
        uu.save()
        UserProfile.objects.create(user=uu, mobile=mobile)
        return Response(status=200)

    if User.objects.filter(username=email).exclude(id=id_).exists():
        return JsonResponse(status=400, data={'error': 'This email address already registered'})

    if UserProfile.objects.filter(mobile=mobile).exclude(id=id_).exists():
        return JsonResponse(status=400, data={'error': 'This phone number already registered'})

    dd = User.objects.get(id=id_)
    dd.first_name = data_['full_name']
    dd.email = data_['email']
    if password:
        dd.set_password(password)

    if mobile:
        up_, _ = UserProfile.objects.get_or_create(user=dd)
        up_.mobile = mobile
        up_.save()
    dd.save()

    return Response(status=200)


@api_view(['POST'])
@login_required
def edit_profile(request):
    name = request.POST['full_name']
    email = request.POST['email'].lower().strip()

    if User.objects.filter(username=email).exclude(id=request.user.id).exists():
        return Response(status=400, data={'error': 'This email address already exists'})

    u_ = request.user
    u_.first_name = name
    u_.username = email
    u_.save()

    if 'img' in request.FILES:
        up, _ = UserProfile.objects.get_or_create(user=u_)
        up.image = request.FILES['img']
        up.save()
    return Response(status=200)


@api_view(['POST'])
@login_required
def change_password(request):
    old_password = request.POST['old_password']
    new_password = request.POST['new_password']
    confirm_password = request.POST['confirm_password']
    current_password = request.user.password

    match_check = check_password(old_password, current_password)
    if not match_check:
        return Response(status=400, data={'error': 'Old Password doesnt match'})

    if new_password != confirm_password:
        return Response(status=400, data={'error': 'Both passwords must match'})

    user = request.user
    user.set_password(new_password)
    user.save()
    login(request, user)
    return Response(status=200)


@login_required
def profile_(request):
    company = Company.objects.last()
    return render(request, 'superadmin/profile.html', context={'company': company})


@api_view(['POST'])
@login_required
def edit_company(request):
    company = Company.objects.last()
    if company:
        data_serializer = CompanySerializer(company, data=request.data)
    else:
        data_serializer = CompanySerializer(data=request.data)
    if data_serializer.is_valid():
        data_serializer.save()

        if 'img' in request.FILES:
            company.logo = request.FILES['img']
            company.save()

    response = Response(status=200)
    response.set_cookie(key='company_img', value=company.logo.url)
    response.set_cookie(key='company_name', value=company.title)
    return response


@api_view(['GET'])
@login_required
def get_csrf_token(request):
    csrf_token = get_token(request)
    return Response(status=200, data={'token': csrf_token})

@api_view(['GET'])
def forget_password(request):
    return render(request, 'superadmin/auth/forgetpassword.html')


class Util:
  @staticmethod
  def send_email(data):
    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      from_email=os.environ.get('EMAIL_FROM'),
      to=[data['to_email']]
    )
    email.send()

@api_view(['POST'])
def forget_password_send_email(request):
   
   
    email = request.POST['email'].lower().strip()
   
    # if User.objects.filter(username=email).exists():
    #     user=User.objects.filter(username=email).last()
    #     subject = "Password Reset Requested"
        
    #     return render(request, 'superadmin/auth/reset_password.html',context={'username': email})
    if User.objects.filter(email=email).exists():
        print("Hussain")
        user = User.objects.get(email = email)
        uid = urlsafe_base64_encode(force_bytes(user.id))
        #print('Encoded UID', uid)
        #token = PasswordResetTokenGenerator().make_token(user)
        #print('Password Reset Token', token)
        link = 'http://127.0.0.1:8000/forget_password_send_email/'+uid+'/'
        print('Password Reset Link', link)
        # Send EMail
        body = 'Click Following Link to Reset Your Password '+link
        data = {
            'subject':'Reset Your Password',
            'body':body,
            'to_email':'manzoorhussain075@gmail.com'
        }
        Util.send_email(data)
        return render(request, 'superadmin/auth/reset_password.html',context={'username': email})
        #return attrs
        # else:
        # raise serializers.ValidationError('You are not a Registered User')
        
       # pdb.set_trace()
        # email_template_name = "superadmin/auth/reset_password.html"
        # c = {
        # "email":email,
        # 'domain':'127.0.0.1:8000',
        # 'site_name': 'Website',
        # "uid": urlsafe_base64_encode(force_bytes(user.id)),
        # "user": user,
        # 'token': default_token_generator.make_token(user),
        # 'protocol': 'http',
        # }
        # email = render_to_string(email_template_name, c)
        # try:
        #     send_mail(subject, email, 'manzoor.hussain@ml1.ai' , [user.email], fail_silently=False)
        # except BadHeaderError:
        #     return HttpResponse('Invalid header found.')
        
        # #return redirect ("/password_reset/done/")
        # #print("done")
     
        # return Response(status=400, data={'error': 'This email address already exists'})
    
@api_view(['POST'])
def update_password(request):
   
    new_password = request.POST['password1']
    confirm_password = request.POST['password2']
    email = request.POST['username']
  

   

    if new_password != confirm_password:
        return Response(status=400, data={'error': 'Both passwords must match'})
    
    user =User.objects.filter(username=email).last()
    user.set_password(new_password)
    user.save()
    login(request, user)
    return redirect("login")
    #return render(request, 'superadmin/auth/login.html')


    
# Email Configuration
# EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend"
# EMAIL_HOST = 'smtp.gmail.com'
# EMAIL_PORT = 587
# EMAIL_HOST_USER = os.environ.get('EMAIL_USER')
# EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_PASS')
# EMAIL_USE_TLS = True

