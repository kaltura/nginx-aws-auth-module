import boto3
import sys
import os

if __name__ == '__main__':

    if len(sys.argv) != 6:
        print 'Usage:\n\t%s <role_arn> <role_session_name> <service> <region> <session_duration>' % os.path.basename(__file__)
        sys.exit(1)

    _, role_arn, role_session_name, service, region, session_duration = sys.argv
    session_duration = int(session_duration)

    sts = boto3.client('sts')

    assumed_role = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=role_session_name,
        DurationSeconds=session_duration
    )

    credentials = assumed_role['Credentials']

    print '''
    aws_auth $aws_token {
        access_key %s;
        secret_key %s;
        service %s;
        region %s;
    }
''' % (credentials['AccessKeyId'], credentials['SecretAccessKey'], service, region)

    print '''
        location /proxy/ {
            proxy_pass http://mybucket.s3.%s.amazonaws.com/;
            proxy_set_header X-Amz-Date $aws_auth_date;
            proxy_set_header X-Amz-Content-SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
            proxy_set_header X-Amz-Security-Token %s;
            proxy_set_header Authorization $aws_token;
        }
''' % (region, credentials['SessionToken'])
