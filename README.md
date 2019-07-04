# Nginx AWS Authentication module

Generates the required headers for AWS V4 authentication.

## Build

To link statically against nginx, cd to nginx source directory and execute:

    ./configure --add-module=/path/to/nginx-json-var-module

To compile as a dynamic module (nginx 1.9.11+), use:

    ./configure --add-dynamic-module=/path/to/nginx-json-var-module

In this case, the `load_module` directive should be used in nginx.conf to load the module.

## Configuration

### Sample configuration

```
http {

    ...

    aws_auth $aws_token {
        access_key AKIAIOSFODNN7EXAMPLE;
        signing_key mEcBSVtt6D+SgP1qI824NXhP1LKbCEct+HBqQnPWyJQ=;
        key_scope 20130606/us-east-1/s3/aws4_request;
    }

    server {

        ...

        location /proxy/ {
            proxy_pass http://mybucket.s3.eu-central-1.amazonaws.com/;
            proxy_set_header X-Amz-Date $aws_auth_date;
            proxy_set_header X-Amz-Content-SHA256                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; # no body
            proxy_set_header X-Amz-Security-Token 23HYTMLJluxQL...;
            proxy_set_header Authorization $aws_token;
        }
    }
}
```

### Configuration directives

#### aws_auth
* **syntax**: `aws_auth $variable { ... }`
* **default**: `none`
* **context**: `http`

Creates a new variable that evaluates to the `Authorization` header for AWS authentication.

#### access_key
* **syntax**: `access_key key`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS access key, e.g. AKIAIOSFODNN7EXAMPLE.

#### signing_key
* **syntax**: `signing_key key`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS signing key, base64 encoded, e.g. mEcBSVtt6D+SgP1qI824NXhP1LKbCEct+HBqQnPWyJQ=.
Use the provided generate_temp_token.py script to generate a temporary signing key using STS.

#### key_scope
* **syntax**: `key_scope key`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS key scope, e.g. 20130606/us-east-1/s3/aws4_request.

## Nginx variables

The module adds the following nginx variables:
$aws_auth_date - evaluates to the current GMT date, intended for populating the `X-Amz-Date` header.

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path.

Copyright © Kaltura Inc. All rights reserved.
