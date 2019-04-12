# Getting temporary credentials to AWS
Using 
```
python samlapi.py 
```
you can get temporary credentials in your `~/.aws/credentials` file. 

You should provide your AD credentials when username and password is requested. 

Your credentials are transferred to sts.rootdom.dk using NTLM. 

# preparation 

## aws folder
You **must** provide a credentials file for the connection. 

Please edit `~/.aws/credentials` to contain at least: 


[default]
output = json
region = eu-west-1
aws_access_key_id = 
aws_secret_access_key =

[saml]
output = json
region = eu-west-1
aws_access_key_id = 
aws_secret_access_key =

## python requirements

```
pip install boto
pip install configparser
pip install requests_ntlm
pip install bs4
```
