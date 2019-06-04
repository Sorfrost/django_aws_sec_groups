from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import AwsKey, SecGroup, SecGroupPermission
from .functions import get_sec_groups, authorize_ingress, revoke_ingress, update_db_sec
import json
from django.utils import timezone
from botocore.exceptions import ClientError

# Create your views here.

@login_required
def mainpage_sec(request):
    awskey = AwsKey.objects.get(active=True)
    if awskey.last_used + timezone.timedelta(minutes=10) < timezone.now():
        update_db_sec(awskey.key_id, awskey.key_secret, awskey.region)
    if request.user.is_superuser:
        response = get_sec_groups(awskey.key_id, awskey.key_secret, awskey.region)
        return render(request, 'index.html', context={'secgroups': response['SecurityGroups']})
    secgroups = SecGroupPermission.objects.filter(username=request.user)
    if not secgroups:
        return HttpResponse('Your user is not associated with any security group')
    else:
        filter = [x.GroupName.GroupId for x in secgroups]
        response = get_sec_groups(awskey.key_id, awskey.key_secret, awskey.region, filter=filter)
        print(json.dumps(response, indent=4))
        return render(request, 'index.html', context = {'secgroups' : response['SecurityGroups']})

@login_required
def authorize_ingress_sec(request):
    if request.method == 'POST':
        data = request.POST.copy()
        for x in data:
            if '___cidr' in x:
                cidr = data[x]
                groupid = x.split('___')[0]
                continue
            if '___port' in x:
                port = data[x]
                continue
            if '___description' in x:
                description = data[x]
                continue
        awskey = AwsKey.objects.get(active=True)
        try:
            response = authorize_ingress(awskey.key_id, awskey.key_secret, awskey.region,
                                     groupid, cidr, int(port), description)
            return redirect('/')
        except ClientError as err:
            return HttpResponse(str(err))

@login_required
def revoke_ingress_sec(request):
    if request.method == 'POST':
        data = request.POST.copy()
        for x in data:
            if '___cidr' in x:
                cidr = data[x]
                groupid = x.split('___')[0]
                continue
            if '___port' in x:
                port = data[x]
                continue
        awskey = AwsKey.objects.get(active=True)
        try:
            response = revoke_ingress(awskey.key_id, awskey.key_secret, awskey.region,
                                     groupid, cidr, int(port))
            return redirect('/')
        except ClientError as err:
            return HttpResponse(str(err))
