import os
from django import forms

from civicchoice1 import settings
from .models import *

class UserForm(forms.ModelForm):
    gender_choices = (
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('other', 'Other')
    )
    gender = forms.ChoiceField(choices=gender_choices, widget=forms.RadioSelect())

    class Meta:
        model = User
        fields = ['photo', 'name', 'address', 'district', 'ward', 'gender', 'dob', 'contactno',
                  'panchayat', 'village', 'adhar', 'idcardno', 'rationcardno', 'adharcard', 'idcard']


from django.contrib.auth.hashers import make_password
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Load RSA public key at module-level, done once for performance
public_key_path = os.path.join(settings.BASE_DIR, 'keys', 'public_key.pem')
with open(public_key_path, 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

class LoginForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = Login                   # ✅ This tells Django which DB model to use
        fields = ['email', 'password']  # ✅ Include only relevant fields

    def save(self, commit=True):
        instance = super().save(commit=False)

        # ✅ Securely hash the password with Django's recommended hashers (bcrypt/Argon2)
        instance.password = make_password(self.cleaned_data['password'])

        # ✅ Encrypt the email with RSA public key (store encrypted email as hex)
        email_bytes = self.cleaned_data['email'].encode()
        encrypted_email = public_key.encrypt(
            email_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        instance.email = encrypted_email.hex()

        if commit:
            instance.save()
        return instance


class LoginCheck(forms.Form):
    email=forms.CharField(max_length=100)
    password=forms.CharField(widget=forms.PasswordInput())

class LoginForm1(forms.ModelForm):
      class Meta:
          model=Login
          fields=['email']

class NotificationForm(forms.ModelForm):
    class Meta:
        model=Notifications
        fields=['notification']

class SuggestionForm(forms.ModelForm):
    areachoice=[('Ward wise Issues','Ward wise Issues'),('Campaign Ideas','Campaign Ideas'),('Voter Experience Feedback','Voter Experience Feedback'),('Feedback Candidates','Feedback Candidates')]
    area = forms.ChoiceField(choices=areachoice)
    class Meta:
        model=Suggestion
        fields=['area','suggestion']

class ElectionForm(forms.ModelForm):
    class Meta:
        model=Election
        fields=['electiontype','electiondate','starttime','endtime','details']
        widgets = {
            'electiondate': forms.DateInput(attrs={'type': 'date'}),
            'starttime': forms.TimeInput(attrs={'type': 'time'}),
            'endtime': forms.TimeInput(attrs={'type': 'time'}),
        }

    # starttime = forms.TimeField(input_formats=['%I:%M %p'], widget=forms.TextInput(attrs={'class': 'timepicker'}))
    # endtime = forms.TimeField(input_formats=['%I:%M %p'], widget=forms.TextInput(attrs={'class': 'timepicker'}))
class InformationForm(forms.ModelForm):
    informationchoice=[('Rules and Regulations','Rules and Regulations'),('Election Information','Election Information'),('Online Forum','Online Forum'),('Candidates','Candidates')]
    informationcategory= forms.ChoiceField(choices=informationchoice)
    class Meta:
        model=Information
        fields=['informationcategory','information']

class PoliticalpartiesForm(forms.ModelForm):
    class Meta:
        model=Politicalparties
        fields=['partylogo','partyname']

class ElectionmemberForm(forms.ModelForm):
    class Meta:
        model=ElectionMember
        fields=['photo','name','address','gender','dob','contactno','email','panchayat','municipality','taluk']

class CandidateForm(forms.ModelForm):
    gender_choices=(
        ('Male','Male'),
        ('Female','Female'),
        ('other','other')  
    )
    gender=forms.ChoiceField(choices=gender_choices,widget=forms.RadioSelect())
    class Meta:
        model=Candidate
        fields=['photo','name','address','gender','dob','adhar','idcardno','rationcardno','ward','panchayat','contactno','adharcard','idcard']


class CampaignForm(forms.ModelForm):
    class Meta:
        model=Campaign
        fields=['date','time','venue','details']

class NominationForm(forms.ModelForm):
    class Meta:
        model=Nominationpaper
        fields=['familyname','nameonballotpaper','ward','pincode','party']

class OnlineForumForm(forms.ModelForm):
    class Meta:
        model=CandidateForum
        fields=['topic','description','date','time']

class ChatForm(forms.ModelForm):
    class Meta:
        model=Chat
        fields=['message']

class ComplaintsForm(forms.ModelForm):
    class Meta:
        model=Complaints
        fields=['subject','complaint']
class ReplyForm(forms.ModelForm):
    class Meta:
        model=Complaints
        fields=['reply']


