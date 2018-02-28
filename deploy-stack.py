#!/usr/bin/env python
# pylint: disable=C0301,C0111,R0912,C0103

import boto.cloudformation
import sys
import time
import re
import yaml
import pprint

pp = pprint.PrettyPrinter(indent=2).pprint

def error(msg):
    sys.stderr.write(msg+"\n")

def fatal(msg):
    error(msg)
    sys.exit(1)

def nn(msg):
    if msg is None:
        return ''
    return msg

# on recupere la region au niveau du profile
def getRegion(profile):
    region = boto.config.get('profile %s' % profile, 'region')
    if region is None:
        region = boto.config.get('Credentials', 'region')
    return region

# usage: <profile> <stack name> <template file> <parameters>?
if len(sys.argv) < 5:
    fatal("Ce n'est pas ca, mon ami. Il faut me preciser le profil, le nom du stack, du fichier et des parametres, si tu es vraiment exigeant...")

profile = sys.argv[1]
stackname = sys.argv[2]
s3bucket = sys.argv[3] if len(sys.argv) >= 4 else None
template = sys.argv[4] if len(sys.argv) >= 5 else None
policyFileName = sys.argv[5] if len(sys.argv) >= 6 else None
if len(sys.argv) >= 7:
    region = sys.argv[6]
else:
    region = getRegion(profile)
parametersFileName = sys.argv[7] if len(sys.argv) >= 8 else None

c = boto.cloudformation.connect_to_region(region, profile_name=profile) # TOOD error management
try:
    stacks = c.describe_stacks(stackname)
except boto.exception.BotoServerError:
    stacks = []

if region == 'cn-north-1':
    s3url = "https://s3.{region}.amazonaws.com.cn/{bucket}".format(region=region, bucket=s3bucket)
else:
    s3url = "https://s3-{region}.amazonaws.com/{bucket}".format(region=region, bucket=s3bucket)

parameters = [('S3BucketURL', "{s3url}/init".format(s3url=s3url))]
templateBody = None
templateUrl = None
events = []

if s3bucket is not None:
    templateFile = "{s3url}/init/{template}".format(s3url=s3url, template=template)
    if policyFileName is not None:
        policyURL = "{s3url}/{policyfilename}".format(s3url=s3url, policyfilename=policyFileName)

if templateFile is not None:
    if templateFile.startswith('http'):
        templateUrl = templateFile
    else:
        templateBody = file(templateFile).read()

if parametersFileName is not None:
    parametersFile = open(parametersFileName, 'r')   # TOOD : echeck
    parameters = list(yaml.load(parametersFile).items()) # TOOD : echeck
    pp(parameters)

if len(stacks) > 0:
    stack = stacks[0]
    if stack.stack_status == 'ROLLBACK_COMPLETE':
        print('dropping the stack %s'%stackname)
        print('cowardly exiting...')
        sys.exit(1)
        print(c.delete_stack(stackname))
        if templateUrl != None:
            print('creating the stack %s'%stackname)
            print(c.create_stack(stackname, template_url=templateUrl, parameters=parameters, capabilities=['CAPABILITY_IAM']))
        elif templateBody != None:
            print('creating the stack %s'%stackname)
            print(c.create_stack(stackname, template_body=templateBody, parameters=parameters, capabilities=['CAPABILITY_IAM']))
        else:
            print('stack has been dropped')
            sys.exit(1)
    elif re.match('.*_COMPLETE', stack.stack_status): # TODO : autres ? delete_complete?
        if templateUrl != None:
            print(c.update_stack(stackname, template_url=templateUrl, parameters=parameters, capabilities=['CAPABILITY_IAM'], stack_policy_during_update_url=policyURL))
        elif templateBody != None:
            print(c.update_stack(stackname, template_body=templateBody, parameters=parameters, capabilities=['CAPABILITY_IAM'], stack_policy_during_update_url=policyURL))
        else:
            print('stack is complete')
            sys.exit(1)
    else:
        print("stack allready running! : %s => %s" % (stack.stack_status, stack.stack_status_reason))
else:
    if templateUrl != None:
        print('creating the stack %s'%stackname)
        print templateUrl
        print(c.create_stack(stackname, template_url=templateUrl, parameters=parameters, capabilities=['CAPABILITY_IAM']))
    elif templateBody != None:
        print('creating the stack %s'%stackname)
        print(c.create_stack(stackname, template_body=templateBody, parameters=parameters, capabilities=['CAPABILITY_IAM']))
    else:
        print('stack does not exist')
        sys.exit(1)

#lastMessage=''

while True:
    stack = c.describe_stacks(stackname)[0]
# a reprendre, ca ne marche plus du tout...
#    message='%s => %s' % (stack.stack_status, stack.stack_status_reason)
#    if message != lastMessage:
#        print(message)
#        lastMessage=message
#    newEvents=c.describe_stack_events(stackname)
#    if len(newEvents) != len(events):
#        for eventId in reversed(range(0,len(newEvents)-len(events))):
#            event=newEvents[eventId]
#            now=time.strftime('%H:%M:%S')
#            now=event.timestamp
#            print("\r%s : %s : %s => %s" % (now,event.event_id,event.resource_status,nn(event.resource_status_reason)))
#        events=newEvents
#    else:
    if True: 
        sys.stdout.write('.')
        sys.stdout.flush()
    if re.match('.*_COMPLETE', stack.stack_status):
        print('\nend')
        break
    time.sleep(1)
