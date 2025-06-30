from django.shortcuts import redirect, render,get_object_or_404
from .models import *
from .forms import *
from django.contrib import messages
from django.db.models import Q
from datetime import datetime
from django.http import Http404
from datetime import date
from django.utils.timezone import now
import requests
import random

def indexpage(request):
    return render(request,'indexpage.html')
def contactus(request):
    return render(request,'contactus.html')
def logoutview(request):
    request.session.flush()
    return redirect('indexpage')
def siteadminindex(request):
    user_count = User.objects.count()
    election_count = Election.objects.filter(electiondate__lt=now().date()).count()
    distinct_candidate_count = Nominationpaper.objects.filter(status=1,cancelstatus=0).values('loginid').distinct().count()
    ongoing_elections = Election.objects.filter(electiondate__lte=now(), electiondate__gte=now()).count()
    upcoming_elections = Election.objects.filter(electiondate__gt=now()).count()
    return render(request,'siteadminindex.html',{'user_count': user_count,'election_count':election_count,'distinct_candidate_count': distinct_candidate_count,
        'upcoming_elections': upcoming_elections,'ongoing_elections': ongoing_elections})
   
def adminindex(request):
    user_count = User.objects.count()
    election_count = Election.objects.filter(electiondate__lt=now().date()).count()
    distinct_candidate_count = Nominationpaper.objects.filter(status=1,cancelstatus=0).values('loginid').distinct().count()
    ongoing_elections = Election.objects.filter(electiondate__lte=now(), electiondate__gte=now()).count()
    upcoming_elections = Election.objects.filter(electiondate__gt=now()).count()
    return render(request,'adminindex.html',{'user_count': user_count,'election_count':election_count,'distinct_candidate_count': distinct_candidate_count,
        'upcoming_elections': upcoming_elections,'ongoing_elections': ongoing_elections})

def userindex(request):
    return render(request,'userindex.html')
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
import random
from .utils import decrypt_email  # assumes you have decrypt_email() in utils.py

def loginindex(request):
    if request.method == 'POST':
        form = LoginCheck(request.POST)
        if form.is_valid():
            email_input = form.cleaned_data['email']
            password_input = form.cleaned_data['password']

            # Hardcoded admin accounts
            if email_input == "electionofficer@gmail.com" and password_input == "   ":
                request.session['admin_id'] = "admin"
                return redirect('adminindex')
            if email_input == "admin@gmail.com" and password_input == "Admin@123":
                request.session['siteadmin_id'] = "admin"
                return redirect('siteadminindex')

            # Search for encrypted emails
            found_user = None
            for user in Login.objects.all():
                try:
                    decrypted_email = decrypt_email(user.email)
                    if decrypted_email == email_input:
                        found_user = user
                        break
                except Exception:
                    continue

            if not found_user:
                messages.error(request, 'User does not exist')
                return render(request, 'loginindex.html', {'form': form})

            # Validate password securely
            if check_password(password_input, found_user.password):
                # ✅ Generate OTP
                otp = random.randint(1000, 9999)

                # ✅ Store OTP and user ID in session
                request.session['otp'] = otp
                request.session['login_id'] = found_user.id
                request.session['usertype'] = found_user.usertype  # 🔥 this is what was missing

                # ✅ Send OTP
                if found_user.usertype in ['USER', 'CANDIDATE']:
                    decrypted_email = decrypt_email(found_user.email)
                    
                    # Example: Send via email (replace with SMS if preferred)
                    send_mail(
                        'Your CivicChoice OTP',
                        f'Your OTP for login is: {otp}',
                        'no-reply@civicchoice.com',
                        [decrypted_email],
                        fail_silently=False,
                    )

                    return redirect('login_otpverify')  # Replace with your OTP verification page
                else:
                    messages.error(request, 'Invalid user type')
            else:
                messages.error(request, 'Invalid password')
    else:
        form = LoginCheck()
    
    return render(request, 'loginindex.html', {'form': form})


import random
import requests
from django.shortcuts import render, redirect, get_object_or_404
from .forms import UserForm, LoginForm
from .models import User

def userregistration(request):
    if request.method == 'POST':
        form1 = UserForm(request.POST, request.FILES)
        form2 = LoginForm(request.POST)

        if form1.is_valid() and form2.is_valid():
            # Generate OTP
            otp = random.randint(1000, 9999)

            # Send SMS
            phone_number = form1.cleaned_data['contactno']
            url = "https://www.fast2sms.com/dev/bulkV2"
            payload = f"variables_values={otp}&route=otp&numbers={phone_number}"
            headers = {
                'Content-Type': "application/x-www-form-urlencoded",
                'Cache-Control': "no-cache",
                'authorization': "LMByc5MbsOTHzBnMSlDf9PZSUgnWYQZXQ0eyqo3pUl8RiU695vcjxYBTCxD1",
            }
            requests.post(url, data=payload, headers=headers)

            # Save login with hashed password & encrypted email
            login_instance = form2.save(commit=False)
            login_instance.usertype = "USER"
            login_instance.save()

            # Save user profile
            user_instance = form1.save(commit=False)
            user_instance.loginid = login_instance
            user_instance.save()

            # Store session data
            request.session['userid'] = user_instance.id
            request.session['otp'] = otp
            request.session['usertype'] = "USER"  # Store user type in session
            print(f"Generated OTP for user ID {user_instance.id}: {otp}")

            return redirect('otpverify')
    else:
        form1 = UserForm()
        form2 = LoginForm()

    return render(request, 'userregistration.html', {'form': form1, 'forms': form2})


def otpverify(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')
        userid = request.session.get('userid')

        if str(session_otp) == entered_otp:
            # Clear OTP from session
            request.session['otp'] = None
            return redirect('login')
        else:
            return render(request, 'otpverify.html', {'error': 'Invalid OTP'})

    return render(request, 'otpverify.html')

def login_otpverify(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')
        login_id = request.session.get('login_id')
        usertype = request.session.get('usertype')  # ✅ retrieve user type

        if str(session_otp) == entered_otp:
            # Clear OTP from session
            request.session['otp'] = None

            # Redirect based on user type
            if usertype == 'USER':
                request.session['user_id'] = login_id  # optional: set user session key
                return redirect('userhome')
            elif usertype == 'CANDIDATE':
                request.session['can_id'] = login_id  # optional: set candidate session key
                return redirect('candidatehome')
            else:
                return render(request, 'login-otp.html', {'error': 'Invalid user type'})

        else:
            return render(request, 'login-otp.html', {'error': 'Invalid OTP'})

    return render(request, 'login-otp.html')



def canotpverify(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        canid=request.session.get('userid')
        can=get_object_or_404(Candidate,id=canid)

       
        if str(can.otp) == entered_otp:
            # Optional: clear OTP after success
            can.otp = 0
            can.save()
            return redirect('loginindex')
        else:
            return render(request, 'otpverify.html', {'error': 'Invalid OTP'})
    return render(request, 'otpverify.html')


def adminuserview(request):
    user=User.objects.all().order_by('-id')
    return render(request,'adminuserview.html',{'user':user})
def userview(request):
    user=User.objects.all().order_by('-id')
    return render(request,'userview.html',{'user':user})
def userhome(request):
    return render(request,'userhome.html')


def userprofile(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, 'You are not a valid user, please login and try again')
        return redirect('login')

    logid = get_object_or_404(Login, id=user_id)
    user_instance = get_object_or_404(User, loginid=logid)

    if request.method == 'POST':
        form = UserForm(request.POST, request.FILES, instance=user_instance)
        login_form = LoginForm1(request.POST, instance=logid)

        if form.is_valid() and login_form.is_valid():
            login_form.save()
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('userprofile')
    else:
        form = UserForm(instance=user_instance)
        login_form = LoginForm1(instance=logid)

    return render(request, 'userprofile.html', {'form': form, 'login_form': login_form})



def addnotification(request):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')  # Redirect if not logged in

    if request.method=='POST':
        form1=NotificationForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.save()
            
            return redirect('addnotification')
    else:
        form1=NotificationForm()
    return render(request,'addnotification.html',{'form':form1})
def adminnotificationview(request):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')  # Redirect if not logged in

    user=Notifications.objects.all()
    return render(request,'adminnotificationview.html',{'user':user})
def editnotification(request,id):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    user=get_object_or_404(Notifications,id=id)
    if request.method=='POST':
        form=NotificationForm(request.POST,instance=user)
        if form.is_valid():
            form.save()
            return redirect('adminnotificationview')
    else:
        form=NotificationForm(instance=user)
    return render(request,'editnotification.html',{'form':form})
def deletenotification(request,id):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    user=get_object_or_404(Notifications,id=id)
    user.delete()
    return redirect('adminnotificationview')
def usernotificationview(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    user=Notifications.objects.all()
    return render(request,'usernotificationview.html',{'user':user})

def candidatenotificationview(request):
     user=Notifications.objects.all()
     return render(request,'candidatenotificationview.html',{'user':user})
def addsuggestions(request):
     a=request.session.get('user_id')
     if not a:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
     logid=get_object_or_404(Login,id=a)
     if request.method=='POST':
         form1=SuggestionForm(request.POST)
         if form1.is_valid():
             a=form1.save(commit=False)
             a.loginid=logid
             a.save()
             return redirect('addsuggestions')
     else:
         form1=SuggestionForm()
     return render(request,'addsuggestions.html',{'form':form1})
def candidateaddsuggestion(request):
     a=request.session.get('can_id')
     logid=get_object_or_404(Login,id=a)
     if request.method=='POST':
         form1=SuggestionForm(request.POST)
         if form1.is_valid():
             a=form1.save(commit=False)
             a.loginid=logid
             a.save()
             return redirect('candidateaddsuggestion')
     else:
         form1=SuggestionForm()
     return render(request,'candidateaddsuggestion.html',{'form':form1})


def viewsuggestion(request):
    a=request.session.get('user_id')
    if not a:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    logid=get_object_or_404(Login,id=a)
    user=Suggestion.objects.filter(loginid=logid)
    return render(request,'viewsuggestion.html',{'user':user})

def candidatesuggestionview(request):
     a=request.session.get('can_id')
     logid=get_object_or_404(Login,id=a)
     user=Suggestion.objects.filter(loginid=logid)
     return render(request,'candidatesuggestionview.html',{'user':user})

def editsuggestion(request,id):
    user=get_object_or_404(Suggestion,id=id)
    if request.method=='POST':
        form=SuggestionForm(request.POST,instance=user)
        if form.is_valid():
            form.save()
            return redirect('viewsuggestion')
    else:
        form=SuggestionForm(instance=user)
    return render(request,'editsuggestion.html',{'form':form})

def deletesuggestion(request,id):
    user=get_object_or_404(Suggestion,id=id)
    user.delete()
    return redirect('viewsuggestion')

def candidateeditsuggestion(request,id):
    user=get_object_or_404(Suggestion,id=id)
    if request.method=='POST':
        form=SuggestionForm(request.POST,instance=user)
        if form.is_valid():
            form.save()
            return redirect('candidatesuggestionview')
    else:
        form=SuggestionForm(instance=user)
    return render(request,'candidateeditsuggestion.html',{'form':form})

def candidatedeletesuggestion(request,id):
    user=get_object_or_404(Suggestion,id=id)
    user.delete()
    return redirect('candidatesuggestionview')

def adminsuggestionview(request):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    user=Suggestion.objects.all()
    return render(request,'adminsuggestionview.html',{'user':user})
    
def addelection(request):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    if request.method=='POST':
        form1=ElectionForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.save()
            
            return redirect('adminindex')
    else:
        form1=ElectionForm()
    return render(request,'addelection.html',{'form':form1})

# def adminelectionview(request):
#      user=Election.objects.all()
#      return render(request,'adminelectionview.html',{'user':user})
     
def adminelectionview(request):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    user = Election.objects.all().order_by('-currentdate')  # Latest first
    return render(request, 'adminelectionview.html', {'user': user})
def siteadminelectionview(request):
    user = Election.objects.all().order_by('-currentdate')  # Latest first
    return render(request, 'siteadminelectionview.html', {'user': user})

def editelection(request,id):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    user=get_object_or_404(Election,id=id)
    if request.method=='POST':
        form=ElectionForm(request.POST,instance=user)
        print(form)
        if form.is_valid():
            form.save()
            return redirect('adminelectionview')
    else:
        form=ElectionForm(instance=user)
    return render(request,'editelection.html',{'form':form})


def deleteelection(request,id):
    admin = request.session.get('admin_id')
    if not admin:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login') 
    user=get_object_or_404(Election,id=id)
    user.delete()
    return redirect('adminelectionview')

def userelectionview(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    current_datetime = datetime.now()  
    current_date = current_datetime.date() 
    current_time = current_datetime.time()  

    user = Election.objects.all()
    
    return render(request, 'userelectionview.html', {
        'user': user,
        'current_date': current_date,
        'current_time': current_time
    })

def electionview(request):
    user = Election.objects.all()
    can_id = request.session.get('user_id')
    candidate = get_object_or_404(User, loginid=can_id)
    nominations = Nominationpaper.objects.filter(loginid=candidate)
    sent_ids = nominations.values_list('electionid__id', flat=True)
    result_ids = nominations.filter(electionid__publishstatus=1).values_list('electionid__id', flat=True)
    today = datetime.today().date()

    return render(request, 'electionview.html', {
        'user': user,
        'sent_ids': list(sent_ids),
        'result_ids': list(result_ids), 'today': today
    })
def candidatenominationsent(request):
    user = Election.objects.all()
    can_id = request.session.get('can_id')
    candidate = get_object_or_404(User, loginid=can_id)
    nominations = Nominationpaper.objects.filter(loginid=candidate)
    sent_ids = nominations.values_list('electionid__id', flat=True)
    result_ids = nominations.filter(electionid__publishstatus=1).values_list('electionid__id', flat=True)
    today = datetime.today().date()

    return render(request, 'candidatenominationsent.html', {
        'user': user,
        'sent_ids': list(sent_ids),
        'result_ids': list(result_ids), 'today': today
    })
def candidatevotingelectionview(request):
    current_datetime = datetime.now()  
    current_date = current_datetime.date() 
    current_time = current_datetime.time()  

    user = Election.objects.all()
    
    return render(request, 'candidatevotingelectionview.html', {
        'user': user,
        'current_date': current_date,
        'current_time': current_time
    })
def addinformation(request):
    if request.method=='POST':
        form1=InformationForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.save()
            
            return redirect('adminindex')
    else:
        form1=InformationForm()
    return render(request,'addinformation.html',{'form':form1})
def admininformationview(request):
     user=Information.objects.all()
     return render(request,'admininformationview.html',{'user':user})
def editinformation(request,id):
    user=get_object_or_404(Information,id=id)
    if request.method=='POST':
        form=InformationForm(request.POST,instance=user)
        if form.is_valid():
            form.save()
            return redirect('admininformationview')
    else:
        form=InformationForm(instance=user)
    return render(request,'editinformation.html',{'form':form})
def deleteinformation(request,id):
    user=get_object_or_404(Information,id=id)
    user.delete()
    return redirect('admininformationview')
def userinformationview(request):
     user_id = request.session.get('user_id')
     if not user_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
     user=Information.objects.all()
     return render(request,'userinformationview.html',{'user':user})
def addpoliticalparties(request):
    if request.method=='POST':
        form1=PoliticalpartiesForm(request.POST,request.FILES)
        if form1.is_valid():
             a=form1.save(commit=False)
             a.save()
             return redirect('addpoliticalparties')
    else:
        form1=PoliticalpartiesForm()
    user=Politicalparties.objects.all()
    return render(request,'addpoliticalparties.html',{'form':form1,'user':user})

def deletepoliticalparty(request,id):
    user=get_object_or_404(Politicalparties,id=id)
    user.delete()
    return redirect('addpoliticalparties')
def adminelectiondetails(request):
    user=Election.objects.all()
    return render(request,'adminelectiondetails.html',{'user':user})
def politicalparties(request,id):
     a=get_object_or_404(Election,id=id)
     user=Politicalparties.objects.filter(electionid=a)
     return render(request,'politicalparties.html',{'user':user,'b':a})


def usermemberview(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    user = Nominationpaper.objects.filter(status=1, cancelstatus=0)

    election_types = user.values_list('electionid__electiontype', flat=True).distinct()
    wards = user.values_list('ward', flat=True).distinct()

    selected_election = request.GET.get('electiontype')
    selected_ward = request.GET.get('ward')

    if selected_election and selected_ward:
        user = user.filter(
            electionid__electiontype=selected_election,
            ward=selected_ward)

    return render(request, 'usermemberview.html', {
        'user': user,
        'election_types': election_types,
        'wards': wards,
        'selected_election': selected_election,
        'selected_ward': selected_ward
    })


def votenow(request, id):
    login_id = request.session.get('user_id')

    if not login_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    user = get_object_or_404(User, loginid=login_id)
    userr = get_object_or_404(Login, id=login_id)

    election = get_object_or_404(Election, id=id)

    if VoteNow.objects.filter(loginid=userr, electionid=election).exists():
        messages.error(request, 'You have already voted')
        return redirect('userelectionview')
    else:
        nominations = Nominationpaper.objects.filter(electionid=election,cancelstatus=0,status=1,ward=user.ward)

        return render(request, 'votenow.html', {
            'nominations': nominations,
            'elid': election.id
        })

def candidatevotenow(request, id):
    login_id = request.session.get('can_id')
    can = get_object_or_404(User, loginid=login_id)
    can_login = get_object_or_404(Login, id=login_id)
    election = get_object_or_404(Election, id=id)

    if VoteNow.objects.filter(loginid=can_login, electionid=election).exists():
        messages.error(request, 'You have already voted')
        return redirect('candidatevotingelectionview')

    nominations = Nominationpaper.objects.filter(
        electionid=election,
        cancelstatus=0,
        status=1,
        ward=can.ward
    )

    return render(request, 'candidatevotenow.html', {
        'nominations': nominations,
        'elid': election.id
    })

from .utils import encrypt_candidate_id
def vote(request, id, elid):
    login_id = request.session.get('user_id')
    if not login_id:
        messages.error(request, 'User not logged in')
        return redirect('loginindex')
    logid = get_object_or_404(Login, id=login_id)
    candidate = get_object_or_404(User, id=id)
    election = get_object_or_404(Election, id=elid)

    # 🔥 Encrypt candidate ID
    encrypted_candidate_id = encrypt_candidate_id(candidate.id)

    # 🔥 Save encrypted candidate ID
    VoteNow.objects.create(
        candidateid=encrypted_candidate_id,
        loginid=logid,
        electionid=election
    )

    messages.success(request, "You have successfully voted.")
    return redirect('userelectionview')


def candidatevote(request, id, elid):
    login_id = request.session.get('can_id')
    if not login_id:
        messages.error(request, 'User not logged in')
        return redirect('loginindex')

    logid = get_object_or_404(Login, id=login_id)
    candidate = get_object_or_404(User, id=id)
    election = get_object_or_404(Election, id=elid)

    # 🔥 Encrypt candidate ID
    encrypted_candidate_id = encrypt_candidate_id(candidate.id)

    # 🔥 Save encrypted candidate ID
    VoteNow.objects.create(
        candidateid=encrypted_candidate_id,
        loginid=logid,
        electionid=election
    )

    return redirect('candidatevotingelectionview')

# def countvote(request, id):  
#     election = get_object_or_404(Election, id=id)
#     nominations = Nominationpaper.objects.filter(electionid=election,status=1,cancelstatus=0 )
#     users = []
#     for nomination in nominations:
#         candidate = nomination.loginid  
#         vote_count = VoteNow.objects.filter(candidateid=candidate,electionid=election).count()
#         candidate.vote_count = vote_count
#         users.append(candidate)

#     return render(request, 'countvote.html', {'users': users})
from collections import defaultdict
from .utils import decrypt_candidate_id
from django.shortcuts import render, get_object_or_404
from .models import Election, VoteNow, Nominationpaper

from collections import defaultdict
from django.shortcuts import render, get_object_or_404
from .models import Election, VoteNow, Nominationpaper
from .utils import decrypt_candidate_id

def countvote(request, id):
    election = get_object_or_404(Election, id=id)
    nominations = Nominationpaper.objects.filter(
        electionid=election, status=1, cancelstatus=0
    )

    # Map candidate_id to Nomination
    candidate_map = {}
    for nomination in nominations:
        candidate_id = nomination.loginid.id
        candidate_map[candidate_id] = nomination

    vote_counts = defaultdict(int)

    votes = VoteNow.objects.filter(electionid=election)
    for vote in votes:
        try:
            decrypted_candidate_id = decrypt_candidate_id(vote.candidateid)
            if decrypted_candidate_id in candidate_map:
                vote_counts[decrypted_candidate_id] += 1
        except Exception as e:
            print(f"Error decrypting vote ID {vote.id}: {e}")

    grouped = {}
    for candidate_id, nomination in candidate_map.items():
        vote_count = vote_counts.get(candidate_id, 0)
        nomination.vote_count = vote_count

        ward = nomination.ward
        if ward not in grouped:
            grouped[ward] = []
        grouped[ward].append(nomination)

    return render(request, 'countvote.html', {
        'grouped': grouped,
        'nominations': nominations,
    })


def publishresult(request,id):
    a=get_object_or_404(Election,id=id)
    a.publishstatus=1
    a.save()
    return redirect('adminelectionview')

from collections import defaultdict
from django.shortcuts import render
from .models import Election, VoteNow, Nominationpaper
from .utils import decrypt_candidate_id

def viewallresult(request):
    elections = Election.objects.filter(publishstatus=1).order_by('-electiondate')
    election_results_by_type = {}

    for election in elections:
        # Get all valid nominations for this election
        nominations = Nominationpaper.objects.filter(electionid=election, status=1, cancelstatus=0)
        candidate_map = {}
        ward_nominations = defaultdict(list)

        for nomination in nominations:
            candidate_id = nomination.loginid.id
            candidate_map[candidate_id] = nomination
            ward_nominations[nomination.ward].append(nomination)

        # Decrypt all votes in this election and count
        vote_counts = defaultdict(int)
        votes = VoteNow.objects.filter(electionid=election)
        for vote in votes:
            try:
                decrypted_candidate_id = decrypt_candidate_id(vote.candidateid)
                if decrypted_candidate_id in candidate_map:
                    vote_counts[decrypted_candidate_id] += 1
            except Exception as e:
                print(f"Error decrypting vote ID {vote.id}: {e}")

        # Process each ward
        for ward, nominations_in_ward in ward_nominations.items():
            ward_results = []
            max_votes = 0

            for nomination in nominations_in_ward:
                candidate_id = nomination.loginid.id
                vote_count = vote_counts.get(candidate_id, 0)

                ward_results.append({
                    'election': election,
                    'candidate': nomination.loginid,
                    'party': nomination.party,
                    'ward': ward,
                    'nomination': nomination,
                    'vote_count': vote_count,
                    'is_winner': False,
                })

                if vote_count > max_votes:
                    max_votes = vote_count

            # Mark winner(s)
            for result in ward_results:
                if result['vote_count'] == max_votes and max_votes > 0:
                    result['is_winner'] = True

            # Sort: winner first, then descending by vote count
            ward_results.sort(key=lambda x: (not x['is_winner'], -x['vote_count']))

            # Group under election type and ward
            election_type = election.electiontype
            election_results_by_type.setdefault(election_type, {}).setdefault(ward, []).extend(ward_results)

    return render(request, 'viewallresult.html', {
        'ward_results': election_results_by_type
    })


def candidateviewallresult(request):
    elections = Election.objects.filter(publishstatus=1).order_by('-electiondate')

    election_results_by_type = {}
    for election in elections:
        # Get all valid nominations for this election
        nominations = Nominationpaper.objects.filter(electionid=election, status=1, cancelstatus=0)
        ward_nominations = {}

        for nomination in nominations:
            ward = nomination.ward
            if ward not in ward_nominations:
                ward_nominations[ward] = []
            ward_nominations[ward].append(nomination)

        # Process each ward
        for ward, ward_nom_list in ward_nominations.items():
            ward_results = []
            max_votes = 0

            for nomination in ward_nom_list:
                candidate = nomination.loginid
                vote_count = VoteNow.objects.filter(candidateid=candidate, electionid=election).count()

                ward_results.append({
                    'election': election,
                    'candidate': candidate,
                    'party': nomination.party, 
                    'ward': ward,
                    'nomination': nomination,
                    'vote_count': vote_count,
                    'is_winner': False
                })

                if vote_count > max_votes:
                    max_votes = vote_count

            # Mark winner(s)
            for result in ward_results:
                if result['vote_count'] == max_votes and max_votes > 0:
                    result['is_winner'] = True

            # Sort: winner first, then descending by vote count
            ward_results.sort(key=lambda x: (not x['is_winner'], -x['vote_count']))

            # Group under election type and ward
            election_type = election.electiontype
            if election_type not in election_results_by_type:
                election_results_by_type[election_type] = {}
            if ward not in election_results_by_type[election_type]:
                election_results_by_type[election_type][ward] = []

            election_results_by_type[election_type][ward].extend(ward_results)

    return render(request, 'candidateviewallresult.html', {
        'ward_results': election_results_by_type
    })




# def viewresult(request, id):
#     login_id = request.session.get('user_id')  
#     userr = get_object_or_404(User, loginid__id=login_id)

#     election = get_object_or_404(Election, id=id)
    
#     nominations = Nominationpaper.objects.filter(electionid=election,cancelstatus=0,status=1,loginid__panchayat=userr.panchayat )
#     candidates = Candidate.objects.filter(id__in=nominations.values_list('loginid_id', flat=True))
#     for candidate in candidates:
#         vote_count = VoteNow.objects.filter(candidateid=candidate, electionid=election).count()
#         candidate.vote_count = vote_count 
        
#     return render(request, 'viewresult.html', {
#             'candidates': candidates,
#         })

from collections import defaultdict
from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import User, Login, Election, VoteNow, Nominationpaper
from .utils import decrypt_candidate_id

def viewresult(request, id):
    login_id = request.session.get('user_id')
    if not login_id:
        messages.error(request, 'You are not a valid user, please login and try again')
        return redirect('login')

    user = get_object_or_404(User, loginid__id=login_id)
    election = get_object_or_404(Election, id=id)

    # Fetch candidates contesting in the user's ward
    nominations = Nominationpaper.objects.filter(
        electionid=election, cancelstatus=0, status=1, ward=user.ward
    )

    # Prepare mapping: candidate_id -> Nomination
    candidate_map = {nom.loginid.id: nom for nom in nominations}
    vote_counts = defaultdict(int)

    # Fetch and decrypt votes
    votes = VoteNow.objects.filter(electionid=election)
    for vote in votes:
        try:
            decrypted_candidate_id = decrypt_candidate_id(vote.candidateid)
            if decrypted_candidate_id in candidate_map:
                vote_counts[decrypted_candidate_id] += 1
        except Exception as e:
            print(f"Error decrypting vote ID {vote.id}: {e}")

    # Group results by ward
    grouped = {}
    for candidate_id, nomination in candidate_map.items():
        nomination.vote_count = vote_counts.get(candidate_id, 0)
        candidate = nomination.loginid
        candidate.party = nomination.party
        candidate.ward = nomination.ward

        ward = candidate.ward
        if ward not in grouped:
            grouped[ward] = []
        grouped[ward].append(nomination)  # pass nomination, not candidate

    return render(request, 'viewresult.html', {
        'grouped': grouped,
    })


def candidateviewresult(request, id):
    login_id = request.session.get('can_id')  
    userr = get_object_or_404(User, loginid__id=login_id)

    election = get_object_or_404(Election, id=id)

    nominations = Nominationpaper.objects.filter(
        electionid=election, cancelstatus=0, status=1, ward=userr.ward
    ).select_related('loginid', 'party')

    for nom in nominations:
        vote_count = VoteNow.objects.filter(candidateid=nom.loginid, electionid=election).count()
        nom.vote_count = vote_count  

    return render(request, 'candidateviewresult.html', {'nominations': nominations})

def candidateregistration(request):
    if request.method=='POST':
        form1=CandidateForm(request.POST,request.FILES)
        form2=LoginForm(request.POST)
        if form1.is_valid() and form2.is_valid():
            otp = random.randint(1000, 9999)

            # Send SMS
            phone_number = form1.cleaned_data['contactno']
            # print(phone_number)
            url = "https://www.fast2sms.com/dev/bulkV2"
            payload = f"variables_values={otp}&route=otp&numbers={phone_number}"
            headers = {
                # 'authorization': "LMByc5MbsOTHzBnMSlDf9PZSUgnWYQZXQ0eyqo3pUl8RiU695vcjxYBTCxD1",
                'Content-Type': "application/x-www-form-urlencoded",
                'Cache-Control': "no-cache",
            }
            requests.post(url, data=payload, headers=headers)

            # Save login first
            a = form2.save(commit=False)
            a.usertype = "CANDIDATE"
            a.save()

            # Save user with OTP
            b = form1.save(commit=False)
            b.loginid = a
            b.otp = otp
            b.save()

            # Store user id for verification
            request.session['userid'] = b.id
            return redirect('canotpverify')
    else:
        form1=CandidateForm()
        form2=LoginForm()
    return render(request,'candidateregistration.html',{'form':form1,'forms':form2})
# def candidateregistration(request):
#     if request.method == 'POST':
#         form1 = CandidateForm(request.POST, request.FILES)
#         form2 = LoginForm(request.POST)
#         if form1.is_valid() and form2.is_valid():
#             # Skip OTP temporarily
#             otp = 0  # or any dummy value like 1234

#             # Skip SMS sending
#             # phone_number = form1.cleaned_data['contactno']
#             # url = "https://www.fast2sms.com/dev/bulkV2"
#             # payload = f"variables_values={otp}&route=otp&numbers={phone_number}"
#             # headers = {
#             #     'Content-Type': "application/x-www-form-urlencoded",
#             #     'Cache-Control': "no-cache",
#             # }
#             # requests.post(url, data=payload, headers=headers)

#             # Save login first
#             a = form2.save(commit=False)
#             a.usertype = "CANDIDATE"
#             a.save()

#             # Save user with dummy OTP
#             b = form1.save(commit=False)
#             b.loginid = a
#             b.otp = otp
#             b.save()

#             # Store user id for verification
#             request.session['userid'] = b.id
#             return redirect('canotpverify')  # or skip this too if no verification needed
#     else:
#         form1 = CandidateForm()
#         form2 = LoginForm()
#     return render(request, 'candidateregistration.html', {'form': form1, 'forms': form2})

def candidatehome(request):
    return render(request,'candidatehome.html')
def candidateprofile(request):
    a=request.session.get('can_id')
    logid=get_object_or_404(Login,id=a)
    form = get_object_or_404(User,loginid=logid)
    logdata = get_object_or_404(Login,id=logid.id)
    if request.method=='POST':
        form1=UserForm(request.POST,request.FILES,instance=form)
        form2=LoginForm1(request.POST,instance=logdata)
        if form1.is_valid() and form2.is_valid():
            form2.save()
            form1.save()          
            return redirect('candidateprofile')
    else:
      form1=UserForm(instance=form)
      form2=LoginForm1(instance=logdata)
    today = date.today()
    try:
        today_minus_18 = today.replace(year=today.year - 18)
    except ValueError:
        # Handles Feb 29 for leap years
        today_minus_18 = today.replace(month=2, day=28, year=today.year - 18)
    
    # 🔧 Now pass it to the template
    return render(request, 'candidateprofile.html', {
        'form': form1,
        'forms': form2,
        'today_minus_18': today_minus_18.isoformat()  # 👈 Pass as string
    })
    # return render(request,'candidateprofile.html',{'form':form1,'forms':form2})

def admincandidateview(request):
    user = Candidate.objects.all().order_by('-id')  # latest first
    return render(request, 'admincandidateview.html', {'user': user})


# def candidateelectionview(request):
#      user=Election.objects.all()
#      return render(request,'candidateelectionview.html',{'user':user})


def candidateelectionview(request):
    user = Election.objects.all()
    can_id = request.session.get('can_id')
    candidate = get_object_or_404(User, loginid=can_id)
    nominations = Nominationpaper.objects.filter(loginid=candidate)
    sent_ids = nominations.values_list('electionid__id', flat=True)
    result_ids = nominations.filter(electionid__publishstatus=1).values_list('electionid__id', flat=True)
    today = datetime.today().date()

    return render(request, 'candidateelectionview.html', {
        'user': user,
        'sent_ids': list(sent_ids),
        'result_ids': list(result_ids), 'today': today
    })
from django.contrib import messages
from .models import Campaign

def addcampaign(request):
    a = request.session.get('can_id')
    canid = get_object_or_404(User, loginid=a)

    if request.method == 'POST':
        form1 = CampaignForm(request.POST)
        if form1.is_valid():
            new_campaign = form1.save(commit=False)
            new_campaign.loginid = canid

            date = new_campaign.date
            time = new_campaign.time
            venue = new_campaign.venue
            exists = Campaign.objects.filter(loginid=canid, date=date, time=time, venue=venue).exists()

            if exists:
                messages.success(request, "A campaign is already scheduled at the same venue, date, and time.")
            else:
                new_campaign.save()
                messages.success(request, "Campaign added successfully.")
                return redirect('addcampaign')
    else:
        form1 = CampaignForm()

    return render(request, 'addcampaign.html', {'form': form1})

def usercampaignview(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    user=Campaign.objects.all()
    return render(request,'usercampaignview.html',{'user':user})
def candidatecampaignview(request):
     a=request.session.get('can_id')
     canid=get_object_or_404(User,loginid=a)
     user=Campaign.objects.filter(loginid=canid)
     return render(request,'candidatecampaignview.html',{'user':user})
def editcampaign(request,id):
    can=get_object_or_404(Campaign,id=id)
    if request.method=='POST':
        form=CampaignForm(request.POST,instance=can)
        if form.is_valid():
            form.save()
            return redirect('candidatecampaignview')
    else:
        form=CampaignForm(instance=can)
    return render(request,'editcampaign.html',{'form':form})
def deletecampaign(request,id):
    user=get_object_or_404(Campaign,id=id)
    user.delete()
    return redirect('candidatecampaignview')

def sendnominationpaper(request,id):
    election=get_object_or_404(Election,id=id)
    a=request.session.get('user_id')
    if not a:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    canid=get_object_or_404(User,loginid=a)
    if request.method=='POST':
        form1=NominationForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.electionid=election
            a.loginid=canid
            a.save()
            return redirect('electionview')
    else:
        form1=NominationForm()
    return render(request,'sendnominationpaper.html',{'form':form1,'canid':canid})
def candidatesendnominationpaper(request,id):
    election=get_object_or_404(Election,id=id)
    a=request.session.get('can_id')
    if not a:
        messages.error(request,'You are not a valid user,please login and try again')
        return redirect('login')
    canid=get_object_or_404(User,loginid=a)
    if request.method=='POST':
        form1=NominationForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.electionid=election
            a.loginid=canid
            a.save()
            return redirect('candidatenominationsent')
    else:
        form1=NominationForm()
    return render(request,'sendnominationpaper.html',{'form':form1,'canid':canid})

def nominationview(request):
     a=request.session.get('user_id')
     canid=get_object_or_404(User,loginid=a)
     user=Nominationpaper.objects.filter(loginid=canid)
     return render(request,'nominationview.html',{'user':user})
def candidatenominationview(request):
     a=request.session.get('can_id')
     canid=get_object_or_404(User,loginid=a)
     user=Nominationpaper.objects.filter(loginid=canid)
     return render(request,'candidatenominationview.html',{'user':user})

def cancelstatus(request,id):
    c=get_object_or_404(Nominationpaper,id=id)
    c.cancelstatus=1
    c.save()
    return redirect('candidatenominationview')
def adminnominationview(request,id):
    election=get_object_or_404(Election,id=id)
    user=Nominationpaper.objects.filter(electionid=election)
    return render(request,'adminnominationview.html',{'user':user})
def approvecandidate(request,id,userid):
    a=get_object_or_404(Nominationpaper,id=id)
    b=get_object_or_404(Login,id=userid)
    b.usertype='CANDIDATE'
    b.save()
    a.status=1
    a.save()
    return redirect('adminelectionview')

def approveindependentcandidate(request, id, userid):
    a = get_object_or_404(Nominationpaper, id=id)
    b = get_object_or_404(Login, id=userid)

    if request.method == 'POST':
        c = request.FILES.get('independentpartylogo')
        if c:
            b.usertype = 'CANDIDATE'
            b.save()
            a.status = 1
            a.independentpartylogo = c
            a.save()
            return redirect('adminelectionview')
    
    return render(request, 'uploadlogo.html', {'candidate': a})


def rejectcandidate(request,id):
    b=get_object_or_404(Nominationpaper,id=id)
    b.status=2
    b.save()
    return redirect("adminelectionview") 

def adminapprovedcandidates(request):
    user = Nominationpaper.objects.filter(status=1, cancelstatus=0)

    election_types = user.values_list('electionid__electiontype', flat=True).distinct()
    wards = user.values_list('ward', flat=True).distinct()

    selected_election = request.GET.get('electiontype')
    selected_ward = request.GET.get('ward')

    if selected_election and selected_ward:
        user = user.filter(
            electionid__electiontype=selected_election,
            ward=selected_ward
        )

    return render(request, 'adminapprovedcandidates.html', {
        'user': user,
        'election_types': election_types,
        'wards': wards,
        'selected_election': selected_election,
        'selected_ward': selected_ward,
    })

def candidateview(request):
    user = Nominationpaper.objects.filter(status=1, cancelstatus=0)

    election_types = user.values_list('electionid__electiontype', flat=True).distinct()
    wards = user.values_list('ward', flat=True).distinct()

    selected_election = request.GET.get('electiontype')
    selected_ward = request.GET.get('ward')

    if selected_election and selected_ward:
        user = user.filter(
            electionid__electiontype=selected_election,
            ward=selected_ward
        )

    return render(request, 'candidateview.html', {
        'user': user,
        'election_types': election_types,
        'wards': wards,
        'selected_election': selected_election,
        'selected_ward': selected_ward,
    })

def candidateresultview(request, id):
    election = get_object_or_404(Election, id=id, publishstatus=1)
    can_id = request.session.get('can_id')
    logged_in_candidate = get_object_or_404(User, loginid=can_id)
    own_nomination = Nominationpaper.objects.get(electionid=election,loginid=logged_in_candidate,status=1 )
    ward = own_nomination.ward
    nominations = Nominationpaper.objects.filter(electionid=election,status=1,ward=ward)
    candidates = User.objects.filter(id__in=nominations.values_list('loginid_id', flat=True))
    for candidate in candidates:
        candidate.vote_count = VoteNow.objects.filter(candidateid=candidate,electionid=election).count()
    candidates = sorted(candidates, key=lambda c: c.vote_count, reverse=True)

    return render(request, 'candidateresultview.html', {'candidates': candidates,'nominations':nominations})


def addonlineforum(request):
    if request.method=='POST':
        form1=OnlineForumForm(request.POST)
        if form1.is_valid():
            a=form1.save(commit=False)
            a.save()
            
            return redirect('addonlineforum')
    else:
        form1=OnlineForumForm()
    return render(request,'addonlineforum.html',{'form':form1})


def useronlineforumview(request):
    loginid = request.session.get('user_id')
    forums = CandidateForum.objects.all()
    joined_forums = JoinOnlineForum.objects.filter(userid=loginid).values_list('forumid', flat=True)
    today = date.today()
    return render(request, 'useronlineforumview.html', {
        'user': forums,               
        'joined_forums': joined_forums,'today': today
    })

# def candidateonlineforumview(request):
#      user=CandidateForum.objects.all()
#      return render(request,'candidateonlineforumview.html',{'user':user})
def candidateonlineforumview(request):
    loginid = request.session.get('can_id')
    forums = CandidateForum.objects.all()
    joined_forums = JoinOnlineForum.objects.filter(userid=loginid).values_list('forumid', flat=True)
    today = date.today()  # Get current date

    return render(request, 'candidateonlineforumview.html', {
        'user': forums,               
        'joined_forums': joined_forums,
        'today': today  # Pass it to template
    })

def adminonlineforumview(request):
     user=CandidateForum.objects.all()
     return render(request,'adminonlineforumview.html',{'user':user})
def editonlineforum(request,id):
    user=get_object_or_404(CandidateForum,id=id)
    if request.method=='POST':
        form=OnlineForumForm(request.POST,instance=user)
        if form.is_valid():
            form.save()
            return redirect('adminonlineforumview')
    else:
        form=OnlineForumForm(instance=user)
    return render(request,'editonlineforum.html',{'form':form})
def deleteonlineforum(request,id):
    user=get_object_or_404(CandidateForum,id=id)
    user.delete()
    return redirect('adminonlineforumview')

def  userjoin(request,id):
    a=request.session.get('user_id')
    login= get_object_or_404(Login,id=a)
    forum=get_object_or_404(CandidateForum,id=id)
    JoinOnlineForum.objects.create(userid=login,forumid=forum)
    return redirect('useronlineforumview')

def  candidatejoin(request,id):
    a=request.session.get('can_id')
    login= get_object_or_404(Login,id=a)
    forum=get_object_or_404(CandidateForum,id=id)
    JoinOnlineForum.objects.create(userid=login,forumid=forum)
    return redirect('candidateonlineforumview')
def viewonlineforummembers(request, id):
    user = JoinOnlineForum.objects.filter(forumid=id)
    users = User.objects.all()
    candidates = Candidate.objects.all()
    return render(request, 'viewonlineforummembers.html', {
        'user': user,
        'all_users': users,
        'all_candidates': candidates
    })

def userjoinedforumview(request):
     a=request.session.get('user_id')
     b= get_object_or_404(Login, id=a)
     user = JoinOnlineForum.objects.filter(userid=b)
     return render(request,'userjoinedforumview.html',{'user':user})
def candidatejoinedforumview(request):
     a=request.session.get('can_id')
     b= get_object_or_404(Login, id=a)
     user = JoinOnlineForum.objects.filter(userid=b)
     return render(request,'candidatejoinedforumview.html',{'user':user})
     

def userchat(request, id):
    a = request.session.get('user_id')
    c = request.session.get('can_id')
    print(c)
    if a:
        logid = get_object_or_404(Login, id=a)
        back_url_name = 'userjoinedforumview'  # if user
    else:
        logid = get_object_or_404(Login, id=c)
        back_url_name = 'candidatejoinedforumview'  # if candidate

    # Get the forum by ID
    forum = get_object_or_404(CandidateForum, id=id)

    # Handle message form
    if request.method == 'POST':
        form = ChatForm(request.POST)
        if form.is_valid():
            chat_message = form.save(commit=False)
            chat_message.senderid = logid
            chat_message.forumid = forum
            chat_message.save()
            return redirect('userchat', id=forum.id)
    else:
        form = ChatForm()
    chats = Chat.objects.filter(forumid=forum).order_by('currentdate')

    return render(request, 'userchat.html', {'form': form,'forum': forum,'chats': chats,'chat_user_id': logid.id,'back_url_name': back_url_name,  
    })

def addcomplaint(request):
     a=request.session.get('user_id')
     logid=get_object_or_404(User,id=a)
     if request.method=='POST':
         form1=ComplaintsForm(request.POST)
         if form1.is_valid():
             a=form1.save(commit=False)
             a.loginid=logid
             a.save()
             return redirect('addcomplaint')
     else:
         form1=ComplaintsForm()
     return render(request,'addcomplaint.html',{'form':form1})
def viewcomplaint(request):
    a=request.session.get('user_id')
    logid=get_object_or_404(User,id=a)
    user=Complaints.objects.filter(loginid=logid)
    return render(request,'viewcomplaint.html',{'user':user})
def deletecomplaint(request,id):
    user=get_object_or_404(Complaints,id=id)
    user.delete()
    return redirect('viewcomplaint')

def admincomplaintview(request):
    user=Complaints.objects.all()
    return render(request,'admincomplaintview.html',{'user':user})

def addreply(request,id):
    user=get_object_or_404(Complaints,id=id)
    if request.method=='POST':
         form=ReplyForm(request.POST)
         if form.is_valid():
             a=form.cleaned_data['reply']
             user.reply=a
             user.save()
             return redirect('addreply',id=id)
    else:
        form=ReplyForm()
    return render(request,'addreply.html',{'form':form})

             


# def votenow(request, id):
#     login_id = request.session.get('user_id')
#     user = get_object_or_404(User, loginid=login_id)
#     userr = get_object_or_404(Login, id=login_id)
#     election = get_object_or_404(Election, id=id)

#     # Check if already voted
#     if VoteNow.objects.filter(loginid=userr, electionid=election).exists():
#         messages.error(request, 'You have already voted')
#         return redirect('userelectionview')

#     # Ward Election
#     if election.electiontype == 'Ward Election':
#         wardcandidates = Nominationpaper.objects.filter(
#             electionid=election,
#             cancelstatus=0,
#             status=1,
#             ward=user.ward
#         )
#         return render(request, 'votenow.html', {
#             'wardcandidates': wardcandidates,
#             'elid': election.id
#         })

#     # Panchayat Election
#     elif election.electiontype == 'Panchayat Election':
#         # Ward member candidates
#         panchayatcandidates = Nominationpaper.objects.filter(
#             electionid=election,
#             cancelstatus=0,
#             status=1,
#             panchayat=user.panchayat
#         )


#         return render(request, 'votenow.html', {
#             'panchayatcandidates': panchayatcandidates,
#             'elid': election.id
#         })

     