# Getting temporary credentials to AWS
Using `aws-login.bat`, you can get temporary credentials in your `~/.aws/credentials` file. 

You should provide your AD credentials when username and password is requested. 

Your credentials are transferred to sts.rootdom.dk using NTLM. 

## AWS configuration
You **must** provide a credentials file for the connection. 

Please edit `~/.aws/credentials` to contain at least: 


    [default]
    output = json
    region = eu-west-1
    aws_access_key_id = 
    aws_secret_access_key =


## Python requirements

```
pip install boto
pip install boto3
pip install configparser
pip install requests_ntlm
pip install bs4
```

## Installation

Copy this directory to `c:\program files\aws-login` and add the directory to `%PATH%`.

To run, simply type `aws-login` from any directory.

