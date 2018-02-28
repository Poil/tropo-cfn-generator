#!/usr/bin/python
# coding=UTF-8
# pylint: disable=C0301,C0111,R0912,C0103

import boto.s3
import boto.cloudformation
from subprocess import call, Popen
import argparse
import ConfigParser, os, glob
import sys

def getRegion(profile):
    region = boto.config.get('profile %s' % profile, 'region')
    if region is None:
        region = boto.config.get('Credentials', 'region')
    return region


if len(sys.argv) < 2:
    print('I need 2 parameters basename and botoentry')
    sys.exit(1)

basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
basename = sys.argv[1]
profile = sys.argv[2]
stackname = sys.argv[3]
prefix = sys.argv[4] if len(sys.argv) >= 5 else None
if len(sys.argv) >= 6:
    region = sys.argv[5]
else:
    region = getRegion(profile)
local_stack = os.path.join(basedir, 'json')

s3_con = boto.s3.connect_to_region(region, profile_name=profile)
my_bucket = s3_con.get_bucket(basename)

os.chdir(local_stack)
for tpl in glob.glob(stackname+'*.json'):
    key = my_bucket.new_key(prefix+tpl)
    print key.set_contents_from_filename(os.path.join(local_stack, tpl))

# End Upload to S3 Bucket

