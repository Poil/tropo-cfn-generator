#!/usr/bin/python
# coding=UTF-8

import boto.s3
import boto.cloudformation
from subprocess import call, Popen
import argparse
import ConfigParser, os, sys

def getRegion(profile):
    region=boto.config.get('profile %s' % profile,'region')
    if region is None:
        region=boto.config.get('Credentials','region')
    return region


if len(sys.argv) < 3:
    fatal('I need 3 parameters : stackname, basename and botoentry')

basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
basename = sys.argv[1]
profile = sys.argv[2]
bucket = sys.argv[3]
if len(sys.argv) >= 5:
    region = sys.argv[4]
else:
    region = getRegion(profile)
local_policies = os.path.join(basedir, 'common', 'stack-policy')

# Upload policy
try:
    s3_con = boto.s3.connect_to_region(region, profile_name=profile)
    my_bucket = s3_con.get_bucket(bucket)
    
    os.chdir(local_policies)
    plcy_key = my_bucket.new_key('deny-all.template')
    print plcy_key.set_contents_from_filename('deny-all.template')

except boto.exception.BotoServerError as botoError:
    for e in botoError:
        print e

# Secure stack
try:
    cf_con = boto.cloudformation.connect_to_region(region, profile_name=profile)

except boto.exception.BotoServerError as botoError:
    for e in botoError:
        print e
        
t = cf_con.set_stack_policy(basename, stack_policy_url = "https://s3-" + region + ".amazonaws.com/" + bucket + "/deny-all.template")
