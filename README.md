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
pip install boto3
pip install configparser
pip install requests_ntlm
pip install bs4
```

## Installation

Copy this directory to `c:\program files\aws-login` and add the directory to `%PATH%`.

To run, simply type `aws-login` from any directory.

## Useful parameters
### Username
The script will try to guess your username based on the currently logged in user on your machine. If you want to provide this username explicitly, you can do so by using the `-u` or `--username` switch. 

### Domain
The script tries to infer the domain name from OS information, but this guess can bee overridden using the `-d` or `--domain` parameter. Legal values are *polhus* and *jypo*.

### Token duration 
The default token duration is 3600 seconds, aka an hour. This is not much, but reflects the default in iAM. If you have configured the role to allow longer session durations, you probably also want this setting to be higher. (And if you are very carefull you might choose a lower value.) Specify seconds. 28800 is 8 hours. 

### Filter 
If you are a member of many ad-connected groups you might choose to apply a filter using `-f` or `--filter`. The filter is applied as simple in-strings for the arns returned. (So `-f kitprod` will only show roles where `kitprod` is contained in the ARN.) If the filter only match a single role login will happen without further user interaction, why 
```
.\aws-login.bat --filter "arn:aws:iam::648870945036:role/jppol-kitprod-readonly-adfs"
```
will log you in to the  `jppol-kitprod-readonly-adfs` role directly when you have provided your password.

### everything
If you just want to type in everything, you can use the `-a` or `--ask` switch.




