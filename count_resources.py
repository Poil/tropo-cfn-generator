#!/usr/bin/env python
import json,sys;
obj=json.load(sys.stdin)
print len(obj["Resources"])
