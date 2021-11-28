# Nginx AWS Authentication module

Generates the required headers/args for AWS V4 authentication.

## Build

To link statically against nginx, cd to nginx source directory and execute:

    ./configure --add-module=/path/to/nginx-aws-auth-module

To compile as a dynamic module (nginx 1.9.11+), use:

    ./configure --add-dynamic-module=/path/to/nginx-aws-auth-module

In this case, the `load_module` directive should be used in nginx.conf to load the module.

## Configuration

### Sample configuration

```
http {

    ...

    aws_auth $aws_token {
        access_key AKIAIOSFODNN7EXAMPLE;
        secret_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY;
        service s3;
        region us-east-1;
    }

    aws_auth_presign $aws_presigned $aws_token https://mybucket.s3.us-east-1.amazonaws.com/$key_name?X-Amz-Expires=600&X-Amz-Security-Token=$temp_token;

    server {

        ...

        # proxy to s3 - sign using headers
        location /proxy/ {
            proxy_pass https://mybucket.s3.us-east-1.amazonaws.com/;
            proxy_set_header X-Amz-Date $aws_auth_date;
            proxy_set_header X-Amz-Content-SHA256                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; # no body
            proxy_set_header X-Amz-Security-Token 23HYTMLJluxQL...;
            proxy_set_header Authorization $aws_token;
        }

        # redirect to a presigned url - sign using args
        set $temp_token 23HYTMLJluxQL...;  # MUST be uri encoded! (all chars except a-z A-Z 0-9 - . _ ~)

        location ~ /redirect/(?P<key_name>.*) {
            return 307 $aws_presigned;
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

#### aws_auth_presign
* **syntax**: `aws_auth_presign $variable $aws_auth_var url_expr`
* **default**: `none`
* **context**: `http`

Creates a new variable that adds the authorization args to the provided url expression.
`$aws_auth_var` must point to a variable previously defined using the `aws_auth` directive.
`url_expr` can contain variables (e.g. `$uri`).

#### access_key
* **syntax**: `access_key key`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS access key, e.g. AKIAIOSFODNN7EXAMPLE.

#### secret_key
* **syntax**: `secret_key key`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS secret key, e.g. wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.

#### service
* **syntax**: `service srv`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS service, e.g. s3.

#### region
* **syntax**: `region reg`
* **default**: `none`
* **context**: `aws_auth`

Sets the AWS region, e.g. us-east-1.

## Nginx variables

The module adds the following nginx variables:
$aws_auth_date - evaluates to the current GMT date, intended for populating the `X-Amz-Date` header.

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path.

Copyright © Kaltura Inc. All rights reserved.
