#!/usr/bin/python 
 
import sys 
import boto.sts 
import boto.s3 
import requests 
import getpass 
import configparser 
import base64 
import xml.etree.ElementTree as ET 
import os
from bs4 import BeautifulSoup 
from os.path import expanduser 
from urllib.parse import urlparse, urlunparse 
from requests_ntlm import HttpNtlmAuth

######
class ConfigSettings:
	def __init__(self):
		self.username = getpass.getuser()
		self.domain = os.environ['userdomain'].lower()
		self.profile = 'default'

	def askUser(self):
		self.domain = inputWithDefault('Enter domain ({}):', settings.domain)
		self.username = inputWithDefault('Enter username ({}):', settings.username)
		self.profile = inputWithDefault('Enter profile ({}):', settings.profile)
		
	def inputWithDefault (display, default):
		value = input(display.format(default))
		if len(value) == 0: value = default
		return value
		
	def getUsername(self): 
		return self.username + '@' + self.domain + '.rootdom.dk'

	def getPassword(self): 
		return self.password 
 
	def askPassword(self): 
		self.password = getpass.getpass()
		

	def getProfile(self):
		return self.profile

################################################################################
# Functions 

def getAssertionFromResponse(response):
	assertion = ''
	# Decode the response and extract the SAML assertion 
	soup = BeautifulSoup(response.text, features="html.parser") 
	# Look for the SAMLResponse attribute of the input tag (determined by 
	# analyzing the debug print(lines above) )
	for inputtag in soup.find_all('input'): 
	    if(inputtag.get('name') == 'SAMLResponse'): 
	        #print(inputtag.get('value')) 
	        assertion = inputtag.get('value')
	return assertion;
 
################################################################################

##########################################################################
# Variables 
 
# region: The default AWS region that this script will connect 
# to for all API calls 
region = 'eu-west-1' 
 
# output format: The AWS CLI output format that will be configured in the 
# saml profile (affects subsequent CLI calls) 
outputformat = 'json'
 
# awsconfigfile: The file where this script will store the temp 
# credentials under the saml profile 
awsconfigfile = '/.aws/credentials'
 
# SSL certificate verification: Whether or not strict certificate 
# verification is done, False should only be used for dev/test 
sslverification = True 
 
# idpentryurl: The initial URL that starts the authentication process. 
idpentryurl = 'https://sts.rootdom.dk/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices' 

##########################################################################

# Get the federated credentials from the user
settings = ConfigSettings()
print('')
print('Will use the username {0}'.format(settings.getUsername()))
settings.askPassword()

# Initiate session handler 
session = requests.Session() 
 
# Programatically get the SAML assertion 
# Set up the NTLM authentication handler by using the provided credential 
session.auth = HttpNtlmAuth(settings.getUsername(), settings.getPassword(), session) 
 
# Opens the initial AD FS URL and follows all of the HTTP302 redirects 
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0'}
response = session.get(idpentryurl, headers=headers, verify=sslverification) 
 
# Debug the response if needed 
print(response)

assertion = getAssertionFromResponse(response)
 
# Parse the returned assertion and extract the authorized roles 
awsroles = [] 
try:
	root = ET.fromstring(base64.b64decode(assertion))
except: 
	print('An exception occurred using NTLM negotiation. retrying with post to sts.rootdom.dk');
	payload = {'UserName': username, 'Password': password, 'optionForms': 'FormsAuthentication' }
	session.auth = None
	session.get(url = idpentryurl, headers = headers, verify = sslverification)
	response = session.post(url = idpentryurl, headers=headers, verify=sslverification, data = payload)
	assertion = getAssertionFromResponse(response)
	root = ET.fromstring(base64.b64decode(assertion))
	print(root)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'): 
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'): 
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)
 
# Note the format of the attribute value should be role_arn,principal_arn 
# but lots of blogs list it as principal_arn,role_arn so let's reverse 
# them if needed 
for awsrole in awsroles: 
    chunks = awsrole.split(',') 
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0] 
        index = awsroles.index(awsrole) 
        awsroles.insert(index, newawsrole) 
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want, 
# otherwise just proceed 
print("" )
if len(awsroles) > 1: 
    i = 0 
    print("Please choose the role you would like to assume:" )
    for awsrole in awsroles: 
        print('[', i, ']: ', awsrole.split(',')[0] )
        i += 1 

    print("Selection: ", )
    selectedroleindex = input() 
 
    # Basic sanity check of input 
    if int(selectedroleindex) > (len(awsroles) - 1): 
        print('You selected an invalid role index, please try again' )
        sys.exit(0) 
 
    role_arn = awsroles[int(selectedroleindex)].split(',')[0] 
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
 
else: 
    role_arn = awsroles[0].split(',')[0] 
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile
 
# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)
 
# Put the credentials into a specific profile instead of clobbering
# the default credentials
if not config.has_section(settings.getProfile()):
    config.add_section(settings.getProfile())
 
config.set(settings.getProfile(), 'output', outputformat)
config.set(settings.getProfile(), 'region', region)
config.set(settings.getProfile(), 'aws_access_key_id', token.credentials.access_key)
config.set(settings.getProfile(), 'aws_secret_access_key', token.credentials.secret_key)
config.set(settings.getProfile(), 'aws_session_token', token.credentials.session_token)
 
# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n\n----------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename))
print('Note that it will expire at {0}.'.format(token.credentials.expiration))
print('After this time you may safely rerun this script to refresh your access key pair.')
print('To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
print('----------------------------------------------------------------\n\n')

# Use the AWS STS token to list all of the S3 buckets
s3conn = boto.s3.connect_to_region(region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     security_token=token.credentials.session_token)
 
buckets = s3conn.get_all_buckets()
 
print('Simple API example listing all s3 buckets:')
print(buckets)
