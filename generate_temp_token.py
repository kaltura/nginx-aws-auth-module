import hashlib
import base64
import boto3
import hmac
import time
import sys
import os


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def get_signing_key(secret_key, date, region, service):
    result = hmac_sha256('AWS4' + secret_key, date)
    result = hmac_sha256(result, region)
    result = hmac_sha256(result, service)
    result = hmac_sha256(result, 'aws4_request')
    return result


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

    access_key = credentials['AccessKeyId']
    secret_key = credentials['SecretAccessKey']
    session_token = credentials['SessionToken']

    date = time.strftime('%Y%m%d', time.gmtime())

    signing_key = get_signing_key(secret_key, date, region, service)
    key_scope = '%s/%s/%s/aws4_request' % (date, region, service)

    print '''
    aws_auth $aws_token {
        access_key %s;
        signing_key %s;
        key_scope %s;
    }
''' % (access_key, base64.b64encode(signing_key), key_scope)

    print '''
        location /proxy/ {
            proxy_pass http://mybucket.s3.%s.amazonaws.com/;
            proxy_set_header X-Amz-Date $aws_auth_date;
            proxy_set_header X-Amz-Content-SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
            proxy_set_header X-Amz-Security-Token %s;
            proxy_set_header Authorization $aws_token;
        }
''' % (region, session_token)
