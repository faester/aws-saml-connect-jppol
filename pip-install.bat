@echo off 
echo Installing requirements. 
pip install boto3
pip install configparser
pip install requests_ntlm
pip install bs4
echo "foo" >%userprofile%\.pip-install
echo done installing requirements...
