def get_sec_groups(aws_access_key_id, aws_secret_access_key, region_name, filter=None):
    import boto3
    ec2 = boto3.client('ec2', region_name=region_name, aws_access_key_id=aws_access_key_id,
                       aws_secret_access_key=aws_secret_access_key)
    if filter == None:
        response = ec2.describe_security_groups()
    else:
        response = ec2.describe_security_groups(GroupIds=[x for x in filter])
    return response

def authorize_ingress(aws_access_key_id, aws_secret_access_key, region_name, groupid, cidr, port, desc):
    import boto3
    ec2 = boto3.client('ec2', region_name=region_name, aws_access_key_id=aws_access_key_id,
                       aws_secret_access_key=aws_secret_access_key)
    IpPermissions = [{
        'FromPort' : port,
        'ToPort' : port,
        'IpProtocol' : 'TCP',
        'IpRanges' : [{
            'CidrIp' : cidr,
            'Description' : desc
        }]
    }]
    #response = ec2.authorize_security_group_ingress(CidrIp=cidr, FromPort=port, ToPort=port, GroupId=groupid,
    #                                                IpProtocol='TCP')
    response = ec2.authorize_security_group_ingress(GroupId=groupid, IpPermissions=IpPermissions)
    return response

def revoke_ingress(aws_access_key_id, aws_secret_access_key, region_name, groupid, cidr, port):
    import boto3
    ec2 = boto3.client('ec2', region_name=region_name, aws_access_key_id=aws_access_key_id,
                       aws_secret_access_key=aws_secret_access_key)
    IpPermissions = [{
        'FromPort' : port,
        'ToPort' : port,
        'IpProtocol' : 'TCP',
        'IpRanges' : [{
            'CidrIp' : cidr
        }]
    }]
    #response = ec2.authorize_security_group_ingress(CidrIp=cidr, FromPort=port, ToPort=port, GroupId=groupid,
    #                                                IpProtocol='TCP')
    response = ec2.revoke_security_group_ingress(GroupId=groupid, IpPermissions=IpPermissions)
    return response

