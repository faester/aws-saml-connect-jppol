# Getting temporary credentials to AWS
Using 
```
python samlapi.py 
```
you can get temporary credentials in your `~/.aws/credentials` file. 

You should provide your AD credentials when username and password is requested. 

Your credentials are transferred to sts.rootdom.dk using NTLM. 

# preparation 

```
pip install boto
pip install requests
pip install urllib.parse
pip install configparser
pip install requests_ntlm
```
