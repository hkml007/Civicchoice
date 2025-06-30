from django.db import models

# Create your models here.
class User(models.Model):
    photo=models.ImageField(upload_to='photo')
    name=models.CharField(max_length=100)
    address=models.CharField(max_length=100)
    district=models.CharField(max_length=100)
    ward=models.CharField(max_length=100)
    gender=models.CharField(max_length=50)
    dob=models.CharField(max_length=100)
    contactno=models.CharField(max_length=100)
    panchayat=models.CharField(max_length=100)
    village=models.CharField(max_length=100)
    adhar=models.CharField(max_length=50,unique=True)
    idcardno=models.CharField(max_length=100)
    otp=models.IntegerField(null=True)
    rationcardno=models.CharField(max_length=50)
    adharcard=models.ImageField(upload_to='photo',null=True)
    idcard=models.ImageField(upload_to='photo',null=True)
    loginid=models.ForeignKey('Login',on_delete=models.CASCADE)

class Login(models.Model):
    email=models.EmailField(unique=True)
    password=models.CharField(max_length=100)
    usertype=models.CharField(max_length=100)
    status=models.IntegerField(default=0)

class Notifications(models.Model):
    notification=models.TextField()
    currentdate=models.DateTimeField(auto_now_add=True)

class Suggestion(models.Model):
    area=models.CharField(max_length=100)
    suggestion=models.TextField()
    loginid=models.ForeignKey('Login',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)

class Election(models.Model):
    electiontype=models.CharField(max_length=50)
    electiondate=models.DateField()
    starttime=models.TimeField()
    endtime=models.TimeField()
    details=models.TextField()
    currentdate=models.DateTimeField(auto_now_add=True)
    publishstatus=models.IntegerField(default=0)

class Information(models.Model):
    informationcategory=models.CharField(max_length=100)
    information=models.TextField()
    currentdate=models.DateTimeField(auto_now_add=True)

class Politicalparties(models.Model):
    partylogo = models.ImageField(upload_to='photos', default='photos/default.png', null=True, blank=True)
    partyname=models.CharField(max_length=50)
    def __str__(self):
        return self.partyname

class ElectionMember(models.Model):
    photo=models.ImageField(upload_to='photo')
    name=models.CharField(max_length=50)
    address=models.CharField(max_length=50)
    gender=models.CharField(max_length=50)
    dob=models.DateField()
    contactno=models.CharField(max_length=10)
    email=models.EmailField(unique=True)
    panchayat=models.CharField(max_length=50,null=True)
    municipality=models.CharField(max_length=50,null=True)
    taluk=models.CharField(max_length=50)
    partyid=models.ForeignKey('Politicalparties',on_delete=models.CASCADE)
    electionid=models.ForeignKey('Election',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)

class VoteNow(models.Model):
    candidateid = models.TextField()
    # candidateid=models.ForeignKey('User',on_delete=models.CASCADE)
    loginid=models.ForeignKey('Login',on_delete=models.CASCADE)
    electionid=models.ForeignKey('Election',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)
    time=models.TimeField(auto_now_add=True)

class Candidate(models.Model):
    photo=models.ImageField(upload_to='photo')
    name=models.CharField(max_length=50)
    address=models.CharField(max_length=50)
    gender=models.CharField(max_length=50)
    dob=models.DateField()
    adhar=models.CharField(max_length=50,unique=True)
    idcardno=models.CharField(max_length=100)
    rationcardno=models.CharField(max_length=50)
    ward=models.CharField(max_length=100)
    panchayat=models.CharField(max_length=100)
    contactno=models.CharField(max_length=10)
    adharcard=models.ImageField(upload_to='photo',null=True)
    idcard=models.ImageField(upload_to='photo',null=True)
    otp=models.IntegerField(null=True)
    loginid=models.ForeignKey('Login',on_delete=models.CASCADE)

class Campaign(models.Model):
    date=models.DateField()
    time=models.TimeField()
    venue=models.CharField(max_length=50)
    details=models.TextField()
    loginid=models.ForeignKey('User',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)

class Nominationpaper(models.Model):
    familyname=models.CharField(max_length=100)
    nameonballotpaper=models.CharField(max_length=50)
    ward=models.CharField(max_length=50)
    pincode=models.CharField(max_length=20)
    cancelstatus=models.IntegerField(default=0)
    party= models.ForeignKey('Politicalparties',on_delete=models.CASCADE,blank=True,null=True)
    independentpartylogo=models.ImageField(upload_to="photo",null=True,blank=True)
    loginid=models.ForeignKey('User',on_delete=models.CASCADE)
    electionid=models.ForeignKey('Election',on_delete=models.CASCADE)
    status=models.IntegerField(default=0)

class CandidateForum(models.Model):
    topic=models.CharField(max_length=100)
    description=models.TextField()
    date=models.DateField()
    time=models.TimeField()
    currentdate=models.DateTimeField(auto_now_add=True)

class JoinOnlineForum(models.Model):
    forumid=models.ForeignKey('CandidateForum',on_delete=models.CASCADE)
    userid=models.ForeignKey('Login',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)

class Chat(models.Model):
    message=models.CharField(max_length=100)
    senderid=models.ForeignKey('Login',on_delete=models.CASCADE,related_name='sender')
    currentdate=models.DateTimeField(auto_now_add=True)
    time=models.TimeField(auto_now_add=True)
    forumid=models.ForeignKey('CandidateForum',on_delete=models.CASCADE)

class Complaints(models.Model):
    subject=models.CharField(max_length=100)
    complaint=models.TextField()
    loginid=models.ForeignKey('User',on_delete=models.CASCADE)
    currentdate=models.DateTimeField(auto_now_add=True)
    reply=models.TextField()





