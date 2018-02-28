#!/usr/bin/env python
import boto.cloudformation
import sys
import time
import re

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

# usage: <profile> <stack name> 
if len(sys.argv) != 3:
	fatal("Ce n'est pas ca, mon ami. Il faut me preciser le profil et le nom du stack...")

profile=sys.argv[1]
stackName=sys.argv[2]
if len(sys.argv) >= 4:
    region = sys.argv[3]
else:
    region = getRegion(profile)

# TOOD : check profile existence...
c=boto.cloudformation.connect_to_region(region,profile_name=profile)

try:
	stacks=c.describe_stacks(stackName)
except boto.exception.BotoServerError,ex: # TOOD
	fatal('exception pendant le describe du stack %s : %s' % (stackName,str(ex))) # TOOD : stack does not exist...
if len(stacks) == 0:
	fatal('impossible de trouver le stack %s' % stackName)
stack=stacks[0]
print('status du stack %s : %s' % (stackName, stack.stack_status))
print('drop du stack %s' % stackName)		
print(c.delete_stack(stackName))
