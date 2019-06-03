from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import AwsKey, SecGroup, SecGroupPermission
from .functions import get_sec_groups, authorize_ingress, revoke_ingress
import json
from django.utils import timezone

# Create your views here.

@login_required
def mainpage_sec(request):
    awskey = AwsKey.objects.get(active=True)
    if awskey.last_used + timezone.timedelta(days=1) < timezone.now():
        response = get_sec_groups(awskey.key_id, awskey.key_secret, awskey.region)
        for secgroup in response['SecurityGroups']:
            a = SecGroup(GroupId=secgroup['GroupId'], GroupName=secgroup['GroupName'],
                         Description=secgroup['Description'])
            a.save()
        awskey.last_used = timezone.now()
        awskey.save()
    secgroups = SecGroupPermission.objects.filter(username=request.user)
    filter = [x.GroupName.GroupId for x in secgroups]
    response = get_sec_groups(awskey.key_id, awskey.key_secret, awskey.region, filter=filter)
    print(json.dumps(response, indent=4))
    return render(request, 'test.html', context = {'secgroups' : response['SecurityGroups']})

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
        response = authorize_ingress(awskey.key_id, awskey.key_secret, awskey.region,
                                     groupid, cidr, int(port), description)
        if response['ResponseMetadata']['HTTPStatusCode'] ==  200:
            return redirect('/')
        else:
            return HttpResponse('not ok')

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
        response = revoke_ingress(awskey.key_id, awskey.key_secret, awskey.region,
                                     groupid, cidr, int(port))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return redirect('/')
        else:
            return HttpResponse('not ok')


