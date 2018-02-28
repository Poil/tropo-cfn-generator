#!/usr/bin/env python
# pylint: disable=C0301,C0111,R0912
#
# heavy wip
#
from troposphere import Ref, Tags, Template, Base64, Join, Output, Parameter, GetAtt
import troposphere.ec2 as ec2
import troposphere.route53 as route53
import troposphere.s3 as s3
import troposphere.sqs as sqs
import troposphere.iam as iam
import troposphere.elasticloadbalancing as elasticloadbalancing
import troposphere.rds as rds
import troposphere.cloudformation as cloudformation
import troposphere.elasticache as elasticache
import troposphere.cloudfront as cloudfront
import troposphere.autoscaling as autoscaling

import yaml
import sys
import re
import os
import jinja2
import ipaddress
import json
import pickle

# ##############################################################################
# Function
# ##############################################################################
class Loader(yaml.Loader):
    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]
        super(Loader, self).__init__(stream)

    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, Loader)

def fatal(msg):
    sys.stderr.write(msg+"\n")
    sys.exit(1)


def read_yaml(yaml_file):
    Loader.add_constructor('!include', Loader.include)
    with open(yaml_file, 'r') as stream:
        try:
            return yaml.load(stream, Loader)
        except yaml.YAMLError as exc:
            print(exc)
            return False


def hash_value_is(myhash, mykey, values):
    if mykey in myhash:
        if isinstance(values, str):
            return myhash[mykey] == values
        else:
            return myhash[mykey] in values
    else:
        return False


def make_resource_name(resource_name):
    return re.sub(r'[\W_]+', '', resource_name)


def gen_tag_list(tags, propagate=None):
    if propagate != None:
        return [{'PropagateAtLaunch': True, 'Key':tagKey, 'Value':tagValue} for (tagKey, tagValue) in tags.items()]
    else:
        return [{'Key':tagKey, 'Value':tagValue} for (tagKey, tagValue) in tags.items()]


def convert_expression(a, keys):
    ar = re.split('(#{[^}]+})', a)
    ret = []

    for elt in ar:
        if elt != '':
            m = re.match(r'^#{([^}]+)}$', elt)
            if m:
                var = m.group(1)
                ret.append(keys[var])
            else:
                ret.append(elt)
    return ret


def validate_schedule(schedule):
    return re.match(r'^never|non-business-hours|business-hours/\d+-\d+|business-hours-no-autostart/\d+-\d+$', schedule) is not None


def validate_schedule_rds(schedule):
    return re.match(r'^never|non-business-hours|business-hours/\d+-\d+/db\.\w+\.\w+$', schedule) is not None


def is_true(txt): # TOOD : propager !
    return txt.upper() in ['Y', 'YES', 'T', 'TRUE']


def gen_facts(common_facts, object_facts, instance_name=None):
    platforms = {
            'p': 'production',
            'e': 'preproduction',
            'r': 'recette',
            'i': 'integration',
            'q': 'qualification',
            't': 'test',
            'd': 'developpement'
    }
    roles = {
            'b': 'backup',
            'c': 'cache',
            'd': 'databases',
            'i': 'infrastructure',
            'f': 'filer',
            'l': 'ldap',
            'n': 'console',
            'p': 'proxy',
            's': 'stats',
            'w': 'webserver',
            'x': 'indexer',
            'a': 'application',
            'j': 'batch'
    }

    facts_grp = None
    if instance_name:
        facts_grp = re.match(r"\w+-(?P<platform>\w)(?P<role>\w)\d+(-(?P<subrole>\w+))?", instance_name)

    facts = {}
    if facts_grp is not None:
        if facts_grp.group('platform') in platforms:
            facts['platform'] = platforms[facts_grp.group('platform')]
        if facts_grp.group('role') in roles:
            facts['role'] = roles[facts_grp.group('role')]
        if facts_grp.group('subrole'):
            facts['subrole'] = facts_grp.group('subrole')

    # Merge auto instance facts  with instance Facts
    for k, v in facts.iteritems():
        if k not in object_facts:
            object_facts[k] = v

    # Merge default Facts with instance Facts
    for k, v in common_facts.iteritems():
        if k not in object_facts:
            object_facts[k] = v
    return object_facts


def gen_policy(policies, policy_name, obj_type, obj_access, resource):
    if obj_type not in policies or obj_access not in policies[obj_type]:
        sys.exit(101)

    flat_policy = pickle.dumps(policies[obj_type][obj_access]['PolicyDocument'])
    policy = pickle.loads(flat_policy.replace('#{resource}', resource))
    cur_pol = iam.Policy(
            PolicyName=policy_name,
            PolicyDocument=policy
    )

    return cur_pol


# ##############################################################################
# Main
# ##############################################################################
if len(sys.argv) < 2:
    fatal("Il faut preciser le fichier d'instance yaml en parametre, et tout ira bien mon ami!")

BASENAME = sys.argv[1]
BASEDIR = os.path.dirname(os.path.realpath(sys.argv[0]))
USERDATADIR = os.path.join(BASEDIR, BASENAME, 'userdata')
CFINITDIR = os.path.join(BASEDIR, BASENAME, 'cfinit')
COMMONYAMLDIR = os.path.join(BASEDIR, 'common', 'yml')
YAMLDIR = os.path.join(BASEDIR, BASENAME, 'yml')
CUSTOMPOLICYDIR = os.path.join(BASEDIR, BASENAME, 'policy')
TPLDIR = os.path.join(BASEDIR, 'json')

# Main yml file
YAMLFILE = os.path.join(YAMLDIR, BASENAME+'.yml')
COMMONYAMLFILE = os.path.join(COMMONYAMLDIR, 'common.yml')
TEMPLATEFILE = os.path.join(TPLDIR, BASENAME+'.json')
TEMPLATEFILE_SG = os.path.join(TPLDIR, BASENAME+'_SG.json')
TEMPLATEFILE_SNET = os.path.join(TPLDIR, BASENAME+'_SNET.json')

if not os.path.exists(YAMLFILE):
    fatal("Can't find {yamlFile}...").format(yamlFile=YAMLFILE)

COMMONCONF = read_yaml(COMMONYAMLFILE)
CONF = read_yaml(YAMLFILE)

NEWPREFIXSTYLE = ('newPrefixStyle' in CONF)

INSTANCES = CONF.get('instances', {})
LAUNCHCONFIGURATIONS = CONF.get('launch-configurations', {})
AUTOSCALINGGROUPS = CONF.get('autoscaling-groups', {})
RESOURCESPREFIX = CONF['prefix'] if CONF.get('prefix', False) else ''
SECURITYGROUPS = CONF.get('security-groups', {})
S3BUCKETS = CONF.get('s3-buckets', {})
ELBS = CONF.get('elbs', {})
RDSS = CONF.get('rds', {})
SQSS = CONF.get('sqs', {})
CACHES = CONF.get('elasticache', {})
CLOUDFRONTS = CONF.get('cloudfront', {})
GLOBAL_FACTS = CONF.get('facts', {})
ACCOUNT_ID = CONF['account_id']
REGION = CONF['region']
ROUTE53_HOSTED_ZONES = CONF.get('route53', {})
# If route53 main zone is not managed by cloudformation, set R53_HOSTED_ZONE & ZONE
R53_HOSTED_ZONE = CONF.get('r53_hosted_zone', '')
ZONE = CONF.get('zone', '')
DOMAIN = CONF.get('domain', '')
# ELB Account ID is needed for logging to s3
ELB_ACCOUNT_ID = COMMONCONF['elb_account_id'][REGION]
# DNS SRV are global except for vpc tools
DNS_SRV = CONF.get('dns', COMMONCONF['dns'][REGION])

# Internal configuration
WELLKNOWNPORTS=read_yaml(os.path.join(COMMONYAMLDIR, 'ports.yaml'))
GENERICPOLICIES=read_yaml(os.path.join(COMMONYAMLDIR, 'policies.yaml'))

if not 'vpc' in CONF:
    fatal('Pas de VPC !! On se moque de qui?')

VPC = CONF['vpc']
S3BUCKETNAME = CONF.get('s3bucket', None)
if S3BUCKETNAME is not None:
    S3BUCKETURL = 'https://s3-eu-west-1.amazonaws.com/{s3BucketName}'.format(s3BucketName=S3BUCKETNAME)
else:
    S3BUCKETURL = ''

SUBNETS = CONF.get('subnets', {})
KEYPAIR = CONF.get('keypair', '')
DEFAULTAZ = CONF.get('defaultAZ', '')
AMIS = CONF.get('amis', {})

# pylint: disable=C0103
nested_stack = {}
t = Template()
t.add_version('2010-09-09')

t_sg = Template()
t_sg.add_version('2010-09-09')
STACK_SG = {}
STACK_SG['Parameters'] = {}

t_snet = Template()
t_snet.add_version('2010-09-09')
STACK_SNET = {}
STACK_SNET['Parameters'] = {}

# ##############################################################################
# Params
# ##############################################################################
s3_bucket_url = t.add_parameter(Parameter(
    'S3BucketURL',
    Type='String'
))

# ##############################################################################
# VPC
# ##############################################################################
if isinstance(VPC, basestring):
    vpc_id = VPC
else:
    # Build object facts
    if not VPC.get('facts', False):
        VPC['facts'] = {}
    vpcFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=VPC['facts'])

    resourceName = 'TheVPC' # ToDo : generer ?
    vpc_id = Ref(resourceName)
    t.add_resource(ec2.VPC(
        resourceName,
        CidrBlock=VPC['cidr'],
        EnableDnsSupport=True,
        EnableDnsHostnames=True,
        Tags=Tags(
            client=vpcFacts['client_code'],
            project=vpcFacts['project_code'],
            environment=vpcFacts['platform'],
            Name='vpc {client_code} / {project_code}'.format(client_code=vpcFacts['client_code'], project_code=vpcFacts['project_code'])
        )))

# ##############################################################################
# DHCP Option Set
# ##############################################################################
if (ZONE and not R53_HOSTED_ZONE) or (R53_HOSTED_ZONE and not ZONE):
    fatal('zone and r53_hosted_zone must not be set if you want to manage main route53 zone via cloudformation')

if not R53_HOSTED_ZONE:
    try:
        ZONE = (key for key, value in ROUTE53_HOSTED_ZONES.iteritems() if value.get('main', False) == True).next()
    except:
        True

if not ZONE:
    fatal('Can\'t find a main route 53 zone in the configuration files')

r53_domain = '{zone}.{region}.{domain}'.format(zone=ZONE, region=REGION, domain=DOMAIN)

resourceName = make_resource_name('dhcpoptset_{zone}'.format(zone=ZONE))
dhcp_options = t.add_resource(ec2.DHCPOptions(
    resourceName,
    DomainName=r53_domain,
    DomainNameServers=DNS_SRV,
))

resourceName = make_resource_name('dhcpoptset_assoc_{zone}'.format(zone=ZONE))
t.add_resource(ec2.VPCDHCPOptionsAssociation(
    resourceName,
    DhcpOptionsId=Ref(dhcp_options),
    VpcId=vpc_id
))

# ##############################################################################
# INTERNET GATEWAY
# ##############################################################################
igw = None
if VPC.get('igw', False):
    igw = VPC['igw']
else:
    resourceName = 'InternetGateway'
    igw = Ref(resourceName)
    igwName = resourceName
    t.add_resource(ec2.InternetGateway(
        resourceName,
        Tags=Tags(
            client=vpcFacts['client_code'],
            project=vpcFacts['project_code'],
            environment=vpcFacts['platform']
        ))
    )
    t.add_resource(ec2.VPCGatewayAttachment(
            'InternetGatewayAttachment',
            InternetGatewayId=igw,
            VpcId=vpc_id
        )
    )
    # Clear
    del vpcFacts

# ##############################################################################
# ROUTE 53
# ##############################################################################
if ROUTE53_HOSTED_ZONES:
    for (r53k, r53v) in ROUTE53_HOSTED_ZONES.items():
        r53_resource_name = make_resource_name('r53_'+r53k)
        if r53v['type'] == 'public':
            r53 = t.add_resource(route53.HostedZone(
                r53_resource_name,
                Name=r53v['name'],
                HostedZoneConfig=route53.HostedZoneConfiguration(Comment=r53v.get('description', ''))
            ))
        elif r53v['type'] == 'private':
            vpcs = []
            vpcs.append(route53.HostedZoneVPCs(VPCId=vpc_id, VPCRegion=REGION))
            if r53v.get('vpc', False):
                for c_vpc, c_region in r53v['vpc'].iteritems():
                    vpcs.append(route53.HostedZoneVPCs(VPCId=c_vpc, VPCRegion=c_region))

            # Crado fix for main domain
            c_r53_domain = '{zone}.{region}.{domain}'.format(zone=r53k, region=REGION)

            r53 = t.add_resource(route53.HostedZone(
                r53_resource_name,
                Name=r53v.get('name', c_r53_domain),
                HostedZoneConfig=route53.HostedZoneConfiguration(Comment=r53v.get('description', '')),
                VPCs=vpcs
            ))

            if r53v.get('main', False):
                if R53_HOSTED_ZONE:
                    sys.exit('Error {r53_domain} is declared as main domain but there is already a main domain').format(r53_domain=r53k)
                else:
                    R53_HOSTED_ZONE = Ref(r53_resource_name).data
        else:
            sys.exit('Error {r53_domain} missing a domain type public/private').format(r53_domain=r53k)

# ##############################################################################
# SECURITY GROUPS
# ##############################################################################
if SECURITYGROUPS:
    nested_stack['StackSecurityGroup'] = True
    for (sgk, sgv) in SECURITYGROUPS.items():
        # Build object facts
        if not sgv.get('facts', False):
            sgv['facts'] = {}
        sgFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=sgv['facts'])

        resourceName = make_resource_name(sgk)
        if 'desc' in sgv:
            description = sgv['desc']
        else:
            description = 'pas de description pour le security group {sgName}'.format(sgName=sgk)
        sg = t_sg.add_resource(ec2.SecurityGroup(
            resourceName,
            GroupDescription=description,
            SecurityGroupEgress=[],
            SecurityGroupIngress=[],
            VpcId=vpc_id,
            Tags=Tags(
                client=sgFacts['client_code'],
                project=sgFacts['project_code'],
                environment=sgFacts['platform'],
                Name=sgk
            )
        ))
        t_sg.add_output(Output(
            resourceName+'Id',
            Value=Ref(resourceName)
        ))

        # Clear
        del sgFacts

        egress = []
        ingress = []
        # TOOD : factoriser bon sang !!
        inputs = sgv.get('in', [])
        inputs = [inputs] if isinstance(inputs, str) else inputs
        outputs = sgv.get('out', [])
        outputs = [outputs] if isinstance(outputs, str) else outputs

        ruleCount = 1
        for (rules, sgRulesList, sgTargetType, sgRuleType, sgKey) in ((inputs, sg.SecurityGroupIngress, 'SourceSecurityGroupId', ec2.SecurityGroupIngress, 'in'), (outputs, sg.SecurityGroupEgress, 'DestinationSecurityGroupId', ec2.SecurityGroupEgress, 'out')):
            for rule in rules:
                arule = rule.split(':') # TOOD : format check...
                protocol = arule[0]

                if protocol == 'any':
                    ipProtocol = '-1'
                    ports = [{'fromport': -1, 'toport': -1}]
                    targets = arule[1].split(',')
                elif protocol == 'icmp':
                    ipProtocol = protocol
                    ports = [{'fromport': -1, 'toport': -1}]
                    targets = arule[1].split(',')
                elif protocol in ['tcp', 'udp']:
                    ipProtocol = protocol
                    if arule[1] == 'any':
                        ports = [{'fromport': -1, 'toport': -1}]
                    else:
                        ports = []
                        for port in arule[1].split(','):
                            if not '-' in port:
                                if port in WELLKNOWNPORTS:
                                    ports.append({'fromport': WELLKNOWNPORTS[port], 'toport': WELLKNOWNPORTS[port]})
                                else:
                                    try:
                                        ports.append({'fromport': int(port), 'toport': int(port)})
                                    except ValueError: # port is not an int
                                        fatal("Port {port} inconnu !").format(port=port)
                            else:
                                try:
                                    ports.append({'fromport': int(port.split('-')[0]), 'toport': int(port.split('-')[1])})
                                except ValueError: # port is not an int
                                    fatal("Port {port} inconnu !").format(port=port)
                    targets = arule[2].split(',')
                else:
                    fatal("protocole inconnu : {protocol}").format(protocol=protocol)
                for otarget in targets:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', otarget):
                        targetType = 'CidrIp'
                        target = '{net}/32'.format(net=otarget)
                    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', otarget):
                        targetType = 'CidrIp'
                        target = otarget
                    elif otarget.startswith('sg-'):
                        targetType = sgTargetType
                        target = otarget
                    else:
                        targetType = sgTargetType
                        target = Ref(make_resource_name(otarget))
                    for port in ports:
                        if(protocol in ['tcp', 'udp'] and port['fromport'] == -1):
                            fromPort = 0
                            toPort = 65535
                        else:
                            fromPort = port['fromport']
                            toPort = port['toport']

                        if targetType == sgTargetType:
                            cfnRule = t_sg.add_resource(sgRuleType(
                                make_resource_name(resourceName+'Rule'+sgKey.title()+ipProtocol.title()+'From'+str(fromPort)+'To'+str(toPort)+'Dest'+otarget),
                                IpProtocol=ipProtocol,
                                FromPort=fromPort,
                                ToPort=toPort,
                                GroupId=Ref(resourceName)
                            ))
                            cfnRule.__setattr__(targetType, target)
                            ruleCount += 1
                        else:
                            cfnRule = ec2.SecurityGroupRule(
                                IpProtocol=ipProtocol,
                                FromPort=fromPort,
                                ToPort=toPort
                            )
                            cfnRule.__setattr__(targetType, target)
                            sgRulesList.append(cfnRule)


# ##############################################################################
# ROUTE TABLES
# ##############################################################################
routeCount = 1
routeTableHash = {}
routeTablesRef = []
routeInstances = {}
if 'route-tables' in CONF:
    for (routeTablek, routeTablev) in CONF['route-tables'].items():
        # Build object facts
        if not routeTablev.get('facts', False):
            routeTablev['facts'] = {}
        rtFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=routeTablev['facts'])

        if routeTablev and 'id' in routeTablev: # RouteTable existante
            routeTableRef = routeTablev['id']
        else: #  sinon, on la cree
            resourceName = make_resource_name(routeTablek)
            if routeTablev['propagation'] == True:
                routeTablesRef.append(Ref(resourceName,))

            routeTableRef = Ref(resourceName)
            t_snet.add_resource(ec2.RouteTable(
                resourceName,
                VpcId=vpc_id,
                Tags=Tags(
                    client=rtFacts['client_code'],
                    project=rtFacts['project_code'],
                    environment=rtFacts['platform'],
                    Name=routeTablek)
                )
            )
            # Always needed ?
            if routeTablev and 'vgw' in routeTablev: # virtual gateway : ugly...
                t_snet.add_resource(ec2.VPNGatewayRoutePropagation(
                    make_resource_name(routeTablek)+'vgwRoutePropagation', # TOOD : peut-il y en avoir plusieurs ?? wicked...
                    RouteTableIds=[routeTableRef], # TOOD: bon ?
                    VpnGatewayId=routeTablev['vgw']))
            t_snet.add_output(Output(
                resourceName+'Id',
                Value=Ref(resourceName)
            ))
        del rtFacts

        routeTableHash[routeTablek] = routeTableRef # TOOD?
        if routeTablev and 'routes' in routeTablev: # RouteTable existante
            for route in routeTablev['routes']:
                routeCount += 1
                via = route['via']
                to = route['to']

                if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', to):
                    routeTo = 'To' +  str(int(ipaddress.IPv4Network(unicode(to))[0]))
                elif re.match(r'\d+\.\d+\.\d+\.\d+', to):
                    routeTo = 'To' +  str(int(ipaddress.IPv4Address(unicode(to))))
                else:
                    routeTo = 'To' + to.title()

                if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', via):
                    routeTo = 'Via' +  str(int(ipaddress.IPv4Network(unicode(via))[0]))
                elif re.match(r'\d+\.\d+\.\d+\.\d+', via):
                    routeVia = 'Via' + str(int(ipaddress.IPv4Address(unicode(via))))
                elif via == 'internet-gateway':
                    routeVia = 'Via' + igwName.title()
                else:
                    routeVia = 'Via' + via.title()

                routeresourceName = make_resource_name(routeTablek+routeTo+routeVia)
                # local or vgw
                if via == 'local' or via.startswith('vgw-'):
                    t_snet.add_resource(ec2.Route(
                        routeresourceName,
                        DestinationCidrBlock=to,
                        GatewayId=via,
                        RouteTableId=routeTableRef
                        )
                    )
                elif via.startswith('pcx-'): # vpcpeering
                    t_snet.add_resource(ec2.Route(
                        routeresourceName,
                        DestinationCidrBlock=to,
                        VpcPeeringConnectionId=via,
                        RouteTableId=routeTableRef
                        )
                    )
                elif via == 'internet-gateway':
                    t_snet.add_resource(ec2.Route(
                        routeresourceName,
                        DestinationCidrBlock=to,
                        GatewayId=Ref('InternetGateway'),
                        RouteTableId=routeTableRef
                        )
                    )
                else:
                    routeInstances[routeresourceName] = {}
                    routeInstances[routeresourceName]['DestinationCidrBlock'] = to
                    routeInstances[routeresourceName]['InstanceId'] = Ref(make_resource_name(via))
                    routeInstances[routeresourceName]['RouteTableId'] = resourceName+'Id'

    # Propagate vgw to all routetable that have propagation=true
    # VGW must be defined manually TOOD
    if 'vgw' in CONF:
        t_snet.add_resource(ec2.VPNGatewayRoutePropagation(
            'vgwRoutePropagation',
            RouteTableIds=routeTablesRef,
            VpnGatewayId=CONF['vgw']))

# ##############################################################################
# SUBNETS
# ##############################################################################
subnetsH = {}
if SUBNETS:
    nested_stack['StackSubnet'] = True
    for subnetk, subnetv in SUBNETS.items():
        if isinstance(subnetv, dict):
            # Build object facts
            if not subnetv.get('facts', False):
                subnetv['facts'] = {}
            subnetFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=subnetv['facts'])

            resourceName = make_resource_name(subnetk)
            cidr = subnetv['cidr']
            az = subnetv['az']
            rt = subnetv['rt']
            sn_resource = t_snet.add_resource(ec2.Subnet(
                resourceName,
                VpcId=vpc_id,
                AvailabilityZone=REGION+az,
                CidrBlock=cidr,
                Tags=Tags(
                    client=subnetFacts['client_code'],
                    project=subnetFacts['project_code'],
                    environment=subnetFacts['platform'],
                    Name=subnetk)
                ))
            t_snet.add_resource(ec2.SubnetRouteTableAssociation(
                make_resource_name(subnetk)+'Asso'+make_resource_name(rt),
                RouteTableId=routeTableHash[rt],
                SubnetId=Ref(resourceName))
            )
            subnetsH[subnetk] = Ref(resourceName)
            t_snet.add_output(Output(
                resourceName+'Id',
                Value=Ref(resourceName)
            ))
            # Clear
            del subnetFacts
        else:
            subnetsH[subnetk] = subnetv

# ##############################################################################
# INSTANCES
# ##############################################################################
for (name, details) in INSTANCES.items():
    metadata = ''

    name = make_resource_name(name)
    # Build facts
    if not details.get('facts', False):
        details['facts'] = {}
    instanceFacts = gen_facts(common_facts=GLOBAL_FACTS, instance_name=details['name'], object_facts=details['facts'])

    if details['enabled'].upper() in ('Y', 'YES', 'TRUE'):
        if 'az' in details:
            az = details['az']
        else:
            az = DEFAULTAZ

        # Secondary EBS volume
        if not details.get('disable_data_volume', False):
            volumeName = '{name}DataVolume'.format(name=name)
            volumeTagName = '{name}-data'.format(name=details['name'])

            # Check
            if details.get('volume-type', False) == 'io1':
                if not details.get('iops', False):
                    fatal("EC2 : When volume-type is io1 you need to set IOPS")
                if not 1 <= details['iops'] <= 4000:
                    fatal("EC2 : IOPS must be between 1 and 4000")

            # Required params
            volume_dict = {}
            volume_dict['AvailabilityZone'] = REGION + az
            volume_dict['Size'] = str(details['ebsSize'])
            volume_dict['Tags'] = gen_tag_list({'Name': volumeTagName})

            if details.get('volume-type', False):
                volume_dict['VolumeType'] = details['volume-type']
            else:
                volume_dict['VolumeType'] = 'gp2'

            # Optionals params
            if details.get('auto-enable-io', 'pouet' != 'pouet'):
                volume_dict['AutoEnableIO'] = details['auto-enable-io']
            if details.get('encrypted', 'pouet' != 'pouet'):
                volume_dict['Encrypted'] = details['encrypted']
            if details.get('iops', False):
                volume_dict['Iops'] = details['iops']
            if details.get('kms-key-id', False):
                volume_dict['KmsKeyId'] = details['kms-key-id']
            if details.get('snapshot_id', False):
                volume_dict['SnapshotId'] = details['snapshot_id']

            volume = ec2.Volume.from_dict(volumeName, volume_dict)

        # ApplicationWaitHandle
        waitHandleName = '{name}WaitHandle'.format(name=name)
        waitHandle = cloudformation.WaitConditionHandle(waitHandleName)

        # ApplicationWaitCondition
        waitConditionName = '{name}WaitCondition'.format(name=name)
        waitCondition = cloudformation.WaitCondition(
            waitConditionName,
            DependsOn=name,
            Handle=Ref(waitHandle),
            Timeout="3600",
        )

        # role type ec2
        iamRoleName = '{name}IamRole'.format(name=name)
        instanceRole = iam.Role(iamRoleName,
            Path='/',
            AssumeRolePolicyDocument={
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': ['ec2.amazonaws.com']
                    },
                    'Action': ['sts:AssumeRole']
                }
            ]},
            Policies=[]
        )
        instanceRole.Policies.append(gen_policy(policies=GENERICPOLICIES, obj_type='cfn', obj_access='describe', policy_name='describestacks', resource='*'))
        instanceRole.Policies.append(gen_policy(policies=GENERICPOLICIES, obj_type='r53', obj_access='rw', policy_name='route53update', resource=R53_HOSTED_ZONE))

        if 'policies' in details:
            for polk, polv in details['policies'].items():
                if polv['type'] == 's3':
                    arn_resource = "arn:aws:s3:::{bucket}".format(bucket=polv['bucket'])
                elif polv['type'] == 'ec2':
                    if polv.get('resource', False):
                        arn_resource = polv['resource']
                    else:
                        arn_resource = '*'
                elif polv['type'] == 'sqs':
                    arn_resource = "arn:aws:sqs:{region}:{account_id}:{queue}".format(region=REGION, account_id=ACCOUNT_ID, queue=polv['queue'])
                elif polv['type'] == 'cloudsearch':
                    arn_resource = "arn:aws:cloudsearch:{region}:{account_id}:domain/{domain}".format(region=REGION, account_id=ACCOUNT_ID, domain=polv['domain'])
                else:
                    arn_resource = '*'

                curPol = gen_policy(policies=GENERICPOLICIES, obj_type=polv['type'], obj_access=polv['access'], policy_name=polk, resource=arn_resource)
                instanceRole.Policies.append(curPol)

        userDataValues = dict(zone=ZONE, name=name, hostname=details['hostname'], r53_hosted_zone=R53_HOSTED_ZONE)
        JINJA_USERDATA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(USERDATADIR), autoescape=False)
        tplUserData = JINJA_USERDATA_ENV.get_template(details['user-metadata'])
        baseUserData = tplUserData.render(userDataValues)

        with open(os.path.join(CFINITDIR, details['cloudformation-init']), 'r') as cfinit:
            metadata = eval(cfinit.read())

        if details.get('os_type', 'linux') == 'linux':
            # Fact in cloudformation init
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws'] = {}
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['owner'] = 'root'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['group'] = 'root'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['mode'] = '000755'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content'] = {}
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'] = ['', ['#!/bin/bash\n']]
            for factk, factv in instanceFacts.items():
                metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'][1].append(('echo {key}={value}').format(key=factk, value=factv))
                metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'][1].append('\n')

        iamInstanceProfileName = '{name}IamInstanceProfile'.format(name=name)
        iamInstanceProfile = iam.InstanceProfile(iamInstanceProfileName,
            Path='/',
            Roles=[Ref(iamRoleName)])

        if details['subnetId'].startswith('subnet-'):
            subnet = details['subnetId']
        else:
            subnet = GetAtt('StackSubnet', 'Outputs.'+make_resource_name(details['subnetId']+'Id'))

        if 'availability' in details:
            cur_schedule = details['availability']
            if not validate_schedule(cur_schedule):
                fatal("{schedule} n'est pas une valeur correcte pour {name}.availability").format(cur_schedule, name)
        else:
            cur_schedule = 'non-business-hours' # TOOD : constante !!

        # SourceDestCheck mut be disable for NAT instances
        if details.get('sourceDestCheck', True):
            sourceDestCheck = True
        else:
            sourceDestCheck = details['sourceDestCheck']

        if details.get('rootSize', False):
            root_size = details['rootSize']
        else:
            root_size = '15'

        # Todo to dict to factorize
        if not details.get('disable_data_volume', False):
            # We also need to add a dependsOn route via nat instance if the instance is in a priv network
            if details.get('dependsOn', False):
                instance = ec2.Instance(name,
                    DependsOn=make_resource_name(details['dependsOn']),
                    AvailabilityZone=REGION+az,
                    ImageId=AMIS[details['ami']]['id'], # TOOD : check
                    InstanceType=details['instanceType'],
                    SubnetId=subnet, # TOOD : subnet existant...
                    KeyName=KEYPAIR,
                    DisableApiTermination=False,
                    # TOOD : Windows aussi? Param ? Params type=io1 then iops ... ?
                    BlockDeviceMappings=[{
                            'DeviceName': AMIS[details['ami']]['bootdevice'],
                            'Ebs': {
                                'VolumeSize': root_size,
                                'VolumeType': 'gp2',
                                'DeleteOnTermination': 'false'
                            }
                        },
                        {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}
                    ],
                    # TOOD aussi...
                    Volumes=[{'VolumeId': Ref(volumeName), 'Device': '/dev/sdc'}],
                    IamInstanceProfile=Ref(iamInstanceProfile),
                    Metadata=metadata,
                    SourceDestCheck=sourceDestCheck,
                    SecurityGroupIds=[]
                )
            else:
                instance = ec2.Instance(name,
                    AvailabilityZone=REGION+az,
                    ImageId=AMIS[details['ami']]['id'], # TOOD : check
                    InstanceType=details['instanceType'],
                    SubnetId=subnet, # TOOD : subnet existant...
                    KeyName=KEYPAIR,
                    DisableApiTermination=False,
                    # TOOD : Windows aussi? Param?
                    BlockDeviceMappings=[{
                            'DeviceName': AMIS[details['ami']]['bootdevice'],
                            'Ebs': {
                                'VolumeSize': root_size,
                                'VolumeType': 'gp2',
                                'DeleteOnTermination': 'false'
                            }
                        },
                        {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}
                    ],
                    # TOOD aussi...
                    Volumes=[{'VolumeId': Ref(volumeName), 'Device': '/dev/sdc'}],
                    IamInstanceProfile=Ref(iamInstanceProfile),
                    Metadata=metadata,
                    SourceDestCheck=sourceDestCheck,
                    SecurityGroupIds=[]
                )
        else:
            # We also need to add a dependsOn route via nat instance if the instance is in a priv network
            if details.get('dependsOn', False):
                instance = ec2.Instance(name,
                    DependsOn=make_resource_name(details['dependsOn']),
                    AvailabilityZone=REGION+az,
                    ImageId=AMIS[details['ami']]['id'], # TOOD : check
                    InstanceType=details['instanceType'],
                    SubnetId=subnet, # TOOD : subnet existant...
                    KeyName=KEYPAIR,
                    DisableApiTermination=False,
                    # TOOD : Windows aussi? Param ? Params type=io1 then iops ... ?
                    BlockDeviceMappings=[{
                            'DeviceName': AMIS[details['ami']]['bootdevice'],
                            'Ebs': {
                                'VolumeSize': root_size,
                                'VolumeType': 'gp2',
                                'DeleteOnTermination': 'false'
                            }
                        },
                        {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}
                    ],
                    # TOOD aussi...
                    IamInstanceProfile=Ref(iamInstanceProfile),
                    Metadata=metadata,
                    SourceDestCheck=sourceDestCheck,
                    SecurityGroupIds=[]
                )
            else:
                instance = ec2.Instance(name,
                    AvailabilityZone=REGION+az,
                    ImageId=AMIS[details['ami']]['id'], # TOOD : check
                    InstanceType=details['instanceType'],
                    SubnetId=subnet, # TOOD : subnet existant...
                    KeyName=KEYPAIR,
                    DisableApiTermination=False,
                    # TOOD : Windows aussi? Param?
                    BlockDeviceMappings=[{
                            'DeviceName': AMIS[details['ami']]['bootdevice'],
                            'Ebs': {
                                'VolumeSize': root_size,
                                'VolumeType': 'gp2',
                                'DeleteOnTermination': 'false'
                            }
                        },
                        {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}
                    ],
                    # TOOD aussi...
                    IamInstanceProfile=Ref(iamInstanceProfile),
                    Metadata=metadata,
                    SourceDestCheck=sourceDestCheck,
                    SecurityGroupIds=[]
                )
        if 'security-groups' in details:
            for sg in details['security-groups']:
                if sg.startswith('sg-'):
                    instance.SecurityGroupIds.append(sg)
                else:
                    instance.SecurityGroupIds.append(GetAtt('StackSecurityGroup', 'Outputs.'+make_resource_name(sg+'Id')))

        userData = convert_expression(baseUserData, {
            'AWS::Region' : Ref('AWS::Region'),
            'AWS::StackName' : Ref('AWS::StackName'),
            'r53_hosted_zone': R53_HOSTED_ZONE,
            'ApplicationWaitHandle': Ref(waitHandleName)
        })
        instance.UserData = Base64(Join('', userData))

        if 'privateIp' in details:
            instance.PrivateIpAddress = details['privateIp']

        cur_tags = {
                'Name': name,
                'client': instanceFacts['client_code'],
                'project': instanceFacts['project_code'],
                'schedule': cur_schedule,
                'environment': instanceFacts['platform']
            }

        if 'name' in details:
            cur_tags['Name'] = details['name']
        instance.Tags = gen_tag_list(cur_tags)

        if not details.get('disable_data_volume', False):
            t.add_resource([iamInstanceProfile, instanceRole, volume, instance, waitHandle, waitCondition])
        else:
            t.add_resource([iamInstanceProfile, instanceRole, instance, waitHandle, waitCondition])

    # Public instance have an EIP, it's always created
    if hash_value_is(details, 'public', ['y', 'Y', 't', 'true']):
        if details['enabled'].upper() in ('Y', 'YES', 'TRUE'):
            # TOOD : si igw cree dans mm stack, il faut un dependOn dessus...
            eipResourceName = '{name}EIP'.format(name=name)
            t.add_resource(ec2.EIP(
                eipResourceName,
                InstanceId=Ref(name),
                Domain='vpc'
                )
            )
        else:
            eipResourceName = '{name}EIP'.format(name=name)
            t.add_resource(ec2.EIP(
                eipResourceName,
                Domain='vpc'
                )
            )

# ##############################################################################
# LaunchConfiguration (WIP)
# ##############################################################################
for (name, details) in LAUNCHCONFIGURATIONS.items():
    metadata = ''

    name = '{name}LaunchConfiguration'.format(name=make_resource_name(name))
    # Build facts
    if not details.get('facts', False):
        details['facts'] = {}
    launchConfigurationFacts = gen_facts(common_facts=GLOBAL_FACTS, instance_name=details['name'], object_facts=details['facts'])

    if details['enabled'].upper() in ('Y', 'YES', 'TRUE'):
        # role type ec2
        iamRoleName = '{name}IamRole'.format(name=name)
        launchConfigurationRole = iam.Role(iamRoleName,
            Path='/',
            AssumeRolePolicyDocument={
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': ['ec2.amazonaws.com']
                    },
                    'Action': ['sts:AssumeRole']
                }
            ]},
            Policies=[]
        )
        launchConfigurationRole.Policies.append(gen_policy(policies=GENERICPOLICIES, obj_type='cfn', obj_access='describe', policy_name='describestacks', resource='*'))
        launchConfigurationRole.Policies.append(gen_policy(policies=GENERICPOLICIES, obj_type='r53', obj_access='rw', policy_name='route53update', resource=R53_HOSTED_ZONE))

        if 'policies' in details:
            for polk, polv in details['policies'].items():
                if polv['type'] == 's3':
                    arn_resource = "arn:aws:s3:::{bucket}".format(bucket=polv['bucket'])
                elif polv['type'] == 'ec2':
                    if polv.get('resource', False):
                        arn_resource = polv['resource']
                    else:
                        arn_resource = '*'
                elif polv['type'] == 'sqs':
                    arn_resource = "arn:aws:sqs:{region}:{account_id}:{queue}".format(region=REGION, account_id=ACCOUNT_ID, queue=polv['queue'])
                elif polv['type'] == 'cloudsearch':
                    arn_resource = "arn:aws:cloudsearch:{region}:{account_id}:domain/{domain}".format(region=REGION, account_id=ACCOUNT_ID, domain=polv['domain'])
                else:
                    arn_resource = '*'

                curPol = gen_policy(policies=GENERICPOLICIES, obj_type=polv['type'], obj_access=polv['access'], policy_name=polk, resource=arn_resource)
                launchConfigurationRole.Policies.append(curPol)

        userDataValues = dict(zone=ZONE, name=name, r53_hosted_zone=R53_HOSTED_ZONE)
        JINJA_USERDATA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(USERDATADIR), autoescape=False)
        tplUserData = JINJA_USERDATA_ENV.get_template(details['user-metadata'])
        baseUserData = tplUserData.render(userDataValues)

        with open(os.path.join(CFINITDIR, details['cloudformation-init']), 'r') as cfinit:
            metadata = eval(cfinit.read())

        # Fact in cloudformation init
        if details.get('os_type', 'linux') == 'linux':
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws'] = {}
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['owner'] = 'root'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['group'] = 'root'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['mode'] = '000755'
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content'] = {}
            metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'] = ['', ['#!/bin/bash\n']]
            for factk, factv in launchConfigurationFacts.items():
                metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'][1].append(('echo {key}={value}').format(key=factk, value=factv))
                metadata['AWS::CloudFormation::Init']['config']['files']['/etc/facter/facts.d/aws']['content']['Fn::Join'][1].append('\n')

        iamLaunchConfigurationProfileName = '{name}IamLaunchConfigurationProfile'.format(name=name)
        iamLaunchConfigurationProfile = iam.InstanceProfile(iamLaunchConfigurationProfileName,
            Path='/',
            Roles=[Ref(iamRoleName)])

        if details.get('rootSize', False):
            root_size = details['rootSize']
        else:
            root_size = '15'

        # We also need to add a dependsOn route via nat instance if the instance is in a priv network
        launchConfiguration = autoscaling.LaunchConfiguration(name,
            KeyName=KEYPAIR,
            ImageId=AMIS[details['ami']]['id'], # TOOD : check
            InstanceType=details['instanceType'],
            BlockDeviceMappings=[
                {
                    'DeviceName' : AMIS[details['ami']]['bootdevice'],
                    'Ebs' : {
                        'VolumeSize': root_size,
                        'VolumeType': 'gp2',
                        'DeleteOnTermination': 'true'
                    }
                },
                {
                    'DeviceName' : '/dev/sdb',
                    'VirtualName' : 'ephemeral0'
                },
                {
                    'DeviceName' : '/dev/sdc',
                    'Ebs': {
                        'VolumeSize': str(details['ebsSize']),
                        'VolumeType': 'gp2',
                        'DeleteOnTermination': 'true'
                    }

                }
            ],
            IamInstanceProfile=Ref(iamLaunchConfigurationProfile),
            Metadata=metadata
        )
        if 'security-groups' in details:
            SGs = []
            for sg in details['security-groups']:
                if sg.startswith('sg-'):
                    SGs.append(sg)
                else:
                    SGs.append(GetAtt('StackSecurityGroup', 'Outputs.'+make_resource_name(sg+'Id')))
            launchConfiguration.SecurityGroups = SGs
        else:
            sys.exit('You need some security groups in AutoScalingGroup {1}'.format(name))

        userData = convert_expression(baseUserData, {
            'AWS::Region' : Ref('AWS::Region'),
            'AWS::StackName' : Ref('AWS::StackName'),
            'r53_hosted_zone': R53_HOSTED_ZONE,
            'ApplicationWaitHandle': Ref(waitHandleName)
        })
        launchConfiguration.UserData = Base64(Join('', userData))

        t.add_resource([iamLaunchConfigurationProfile, launchConfigurationRole, launchConfiguration])

# ##############################################################################
# AutoScaling Group (WIP)
# ##############################################################################
for (name, details) in AUTOSCALINGGROUPS.items():
    # Build facts
    if not details.get('facts', False):
        details['facts'] = {}
    autoscalingGroupFacts = gen_facts(common_facts=GLOBAL_FACTS, instance_name=details['name'], object_facts=details['facts'])

    ASname = '{name}AutoscalingGroup'.format(name=make_resource_name(name))
    cur_tags = {
            'Name': name,
            'client': autoscalingGroupFacts['client_code'],
            'project': autoscalingGroupFacts['project_code'],
            'schedule': cur_schedule,
            'environment': autoscalingGroupFacts['platform']
        }
    if 'name' in details:
        cur_tags['Name'] = details['name']

    AZs = []
    for az in details['az']:
        AZs.append(REGION+az)
    AvailabilityZones = AZs

    VPCZIds = []
    for subnet in details['subnets']:
        VPCZIds.append(GetAtt('StackSubnet', 'Outputs.'+make_resource_name(subnet+'Id')))
    VPCZoneIdentifier = VPCZIds

    autoscalingGroup = autoscaling.AutoScalingGroup(
        ASname,
        DesiredCapacity=details['desired-capacity'],
        Tags=[],
        LaunchConfigurationName=Ref(make_resource_name('{name}LaunchConfiguration'.format(name=details['launch-configuration']))),
        MinSize=details['minsize'],
        MaxSize=details['maxsize'],
        VPCZoneIdentifier=VPCZoneIdentifier,
        AvailabilityZones=AvailabilityZones,
        HealthCheckType=details.get('healthchecktype', 'EC2')
        #UpdatePolicy=autoscaling.UpdatePolicy(
        #    AutoScalingRollingUpdate=AutoScalingRollingUpdate(
        #        PauseTime='PT5M',
        #        MinInstancesInService="1",
        #        MaxBatchSize='1',
        #        WaitOnResourceSignals=True
        #    )
        #)
    )
    if details.get('cooldown', False):
        autoscalingGroup.Cooldown = details['cooldown']

    if details.get('loadbalancers', False):
        LBs = []
        for lb in details['loadbalancers']:
            LBs.append(Ref(make_resource_name(lb)))
        autoscalingGroup.LoadBalancerNames = LBs

    autoscalingGroup.Tags = gen_tag_list(tags=cur_tags, propagate=True)
    t.add_resource(autoscalingGroup)

# ##############################################################################
# S3
# ##############################################################################
if S3BUCKETS:
    for (s3k, s3v) in S3BUCKETS.items():
        # Build object facts
        if not s3v.get('facts', False):
            s3v['facts'] = {}
        s3Facts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=s3v['facts'])

        resourceName = make_resource_name(s3k)

        s3bucket = t.add_resource(s3.Bucket(
            resourceName,
            BucketName=s3k,
            Tags=Tags(
                client=s3Facts['client_code'],
                project=s3Facts['project_code'],
                environment=s3Facts['platform']
            )
        ))
        # Clear
        del s3Facts

        if 'access_control' in s3v:
            s3bucket.AccessControl = s3v['access_control']
        # http://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html#example-bucket-policies-use-case-2
        if 'policies' in s3v:
            bucketPolicyName = "{name}BucketPolicy".format(name=resourceName)
            PolicyDocument = {"Statement":[]}

            for policy in s3v['policies']:
                if policy == 's3-putobject':
                    for cur_elb in s3v['policies']['s3-putobject']:
                        PolicyDocument['Statement'].append({
                             "Effect": "Allow",
                             "Action": [
                                 "s3:PutObject",
                             ],
                             "Resource": "arn:aws:s3:::{bucket}/{elb}/AWSLogs/{account_id}/*".format(bucket=s3k, elb=cur_elb, account_id=ACCOUNT_ID),
                             "Principal": {
                                 "AWS": [
                                     ELB_ACCOUNT_ID
                                 ]
                             }
                        })
                elif policy == 's3-ro':
                    if s3v['policies']['s3-ro'].get('canonical-user', False):
                        PolicyDocument['Statement'].append({
                             "Effect": "Allow",
                             "Action": [
                                 "s3:GetObject",
                             ],
                             "Resource": "arn:aws:s3:::{bucket}/*".format(bucket=s3k),
                             "Principal": {
                                 "CanonicalUser": "{canonical_user}".format(canonical_user=s3v['policies']['s3-ro']['canonical-user'])
                             }
                        })
                    else:
                        PolicyDocument['Statement'].append({
                             "Effect": "Allow",
                             "Action": [
                                 "s3:GetObject",
                             ],
                             "Resource": "arn:aws:s3:::{bucket}/*".format(bucket=s3k),
                             "Principal": "*"
                        })
                elif policy == 'custom':
                    with open(os.path.join(CUSTOMPOLICYDIR, s3v['policies']['custom']['src'])) as custom_policy_file:
                        custom_policy = json.load(custom_policy_file)
                    PolicyDocument['Statement'].append(custom_policy)

            t.add_resource(s3.BucketPolicy(
                bucketPolicyName,
                Bucket=Ref(s3bucket),
                PolicyDocument=PolicyDocument
            ))

# ##############################################################################
# ELBs
# ##############################################################################
for elbk, elbv in ELBS.items():
    resourceName = make_resource_name(elbk)
    # Build object facts
    if not elbv.get('facts', False):
        elbv['facts'] = {}
    elbFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=elbv['facts'])

    policies = []

    # Basic support for proxy-protocol
    if hash_value_is(elbv, 'proxy-protocol', ['y', 'Y', 't', 'true']):
        policies.append(elasticloadbalancing.Policy(
            InstancePorts=elbv['proxy-protocol-ports'],
            PolicyName='EnableProxyProtocol',
            PolicyType='ProxyProtocolPolicyType',
            Attributes=[{'Name': 'ProxyProtocol', 'Value': 'true'}]
        ))

    if 'accesslogging' in elbv:
        elb = t.add_resource(elasticloadbalancing.LoadBalancer(
            resourceName,
            DependsOn="{name}BucketPolicy".format(name=make_resource_name(elbv['accesslogging']['bucket'])),
            HealthCheck=elasticloadbalancing.HealthCheck(
                HealthyThreshold=4,
                Interval=15,
                Target='HTTP:80/',
                Timeout=5,
                UnhealthyThreshold=2,
            ),
            Instances=[],
            Listeners=[],
            Scheme='internet-facing' if hash_value_is(elbv, 'public', ['y', 'Y', 't', 'true']) else 'internal',
            SecurityGroups=[],
            Subnets=[],
            CrossZone=True if hash_value_is(elbv, 'crosszone', ['y', 'Y', 't', 'true']) else False,
            Tags=Tags(
                    client=elbFacts['client_code'],
                    project=elbFacts['project_code'],
                    environment=elbFacts['platform'])
            )
        )
        elb.AccessLoggingPolicy = elasticloadbalancing.AccessLoggingPolicy(
            EmitInterval=5,
            Enabled=True,
            S3BucketName=elbv['accesslogging']['bucket'],
            S3BucketPrefix=elbk,
        )
    else:
        elb = t.add_resource(elasticloadbalancing.LoadBalancer(
            resourceName,
            HealthCheck=elasticloadbalancing.HealthCheck(
                HealthyThreshold=4,
                Interval=15,
                Target='HTTP:80/',
                Timeout=5,
                UnhealthyThreshold=2,
            ),
            Instances=[],
            Listeners=[],
            Scheme='internet-facing' if hash_value_is(elbv, 'public', ['y', 'Y', 't', 'true']) else 'internal',
            SecurityGroups=[],
            Subnets=[],
            CrossZone=True if hash_value_is(elbv, 'crosszone', ['y', 'Y', 't', 'true']) else False,
            Tags=Tags(
                    client=elbFacts['client_code'],
                    project=elbFacts['project_code'],
                    environment=elbFacts['platform'])
            )
        )

    if policies:
        elb.Policies = policies

    if elbv['health-protocol'] == 'TCP':
        elb.HealthCheck.Target = '{protocol}:{port}'.format(
            protocol=elbv['health-protocol'],
            port=elbv.get('health-port', '80')
        )
    else:
        elb.HealthCheck.Target = '{protocol}:{port}{health_path}'.format(
            protocol=elbv.get('health-protocol', 'HTTP'),
            port=elbv.get('health-port', '80'),
            health_path=elbv.get('health-path', '/')
        )

    if not 'listeners' in elbv:
        print "Error : {elb} have no listeners".format(elb=elbk)
        break
    for listener in elbv['listeners']:

        # No scoped variable in loops.
        instance_port = None
        instance_protocol = None

        # Accept optional instance port
        if len(listener.split(':')) == 2:
            (protocol, port) = listener.split(':') # TOOD echeck
        elif len(listener.split(':')) == 3:
            (protocol, port, instance_port) = listener.split(':')
        elif len(listener.split(':')) == 4:
            (protocol, port, instance_protocol, instance_port) = listener.split(':')
        else:
            print "Error : {elb} has at least one malformed listener".format(elb=elbk)
            break

        if elbv.get('ssl-certificate-id', False) and protocol == 'HTTPS':
            elb.Listeners.append(
                elasticloadbalancing.Listener(
                    InstancePort=instance_port if instance_port else port,
                    InstanceProtocol=instance_protocol if instance_protocol else protocol,
                    LoadBalancerPort=port,
                    Protocol=protocol,
                    SSLCertificateId=elbv['ssl-certificate-id']
                )
            )
        else:
            elb.Listeners.append(
                elasticloadbalancing.Listener(
                    InstancePort=instance_port if instance_port else port,
                    InstanceProtocol=instance_protocol if instance_protocol else protocol,
                    LoadBalancerPort=port,
                    Protocol=protocol
                )
            )
    # Clear
    del elbFacts

# TOOD : FAC-TO-RI-SER !!!
    if elbv.get('instances', False):
        for instance in elbv['instances']:
            if instance.startswith('i-'):
                elb.Instances.append(instance)
            else:
                elb.Instances.append(Ref(make_resource_name(instance)))
    for securityGroup in elbv['security-groups']:
        if securityGroup.startswith('sg-'):
            elb.SecurityGroups.append(securityGroup)
        else:
            elb.SecurityGroups.append(GetAtt('StackSecurityGroup', 'Outputs.'+make_resource_name(securityGroup+'Id')))
    for subnet in elbv['subnets']:
        if subnet.startswith('subnet-'):
            elb.Subnets.append(subnet)
        else:
            elb.Subnets.append(GetAtt('StackSubnet', 'Outputs.'+make_resource_name(subnet+'Id')))

# ##############################################################################
# RDSs
# ##############################################################################
for rdsk, rdsv in RDSS.items():
    # Build object facts
    if not rdsv.get('facts', False):
        rdsv['facts'] = {}
    rdsFacts = gen_facts(common_facts=GLOBAL_FACTS, object_facts=rdsv['facts'])

    resourceName = make_resource_name(rdsk)

    if rdsv['engine'] == 'mysql':
        family = 'MySQL{maj_version}.{min_version}'.format(maj_version=rdsv['version-major'], min_version=rdsv['version-minor'])
        fullversion = '{maj_version}.{min_version}'.format(maj_version=rdsv['version-major'], min_version=rdsv['version-minor'])
    elif rdsv['engine'] == 'oracle-se1':
        family = 'oracle-se1-{maj_version}'.format(maj_version=rdsv['version-major'])
        fullversion = '{maj_version}.{min_version}'.format(maj_version=rdsv['version-major'], min_version=rdsv['version-minor'])
    else:
        fatal('Limitation : impossible de generer le DB parameter group pour {engine}').format(engine=rdsv['engine'])

    pg = t.add_resource(rds.DBParameterGroup(
        resourceName+'pg',
        Description='DB parameter group pour {name}'.format(name=resourceName),
        Family=family,
        Parameters={},
        Tags=Tags(
                client=rdsFacts['client_code'],
                project=rdsFacts['project_code'],
                environment=rdsFacts['platform'])
    ))

    if 'parameters' in rdsv:
        for (key, value) in rdsv['parameters'].items():
            pg.Parameters[key] = str(value)

    sng = t.add_resource(rds.DBSubnetGroup(
        resourceName+'sng',
        DBSubnetGroupDescription='subnet group for rds {name}'.format(name=resourceName),
        SubnetIds=[]
        )
    )
    for subnet in rdsv['subnets']:
        if subnet.startswith('subnet-'):
            sng.SubnetIds.append(subnet)
        else:
            sng.SubnetIds.append(GetAtt('StackSubnet', 'Outputs.'+make_resource_name(subnet+'Id')))

    if 'availability' in rdsv:
        if not validate_schedule_rds(rdsv['availability']):
            fatal("RDS : {schedule} n'est pas une valeur correcte pour {rds}.availability").format(schedule=cur_schedule, rds=rdsk)
        cur_schedule = '{availability}/{rdsclass}'.format(availability=rdsv['availability'], rdsclass=rdsv['class'])
    else:
        cur_schedule = 'non-business-hours/{rdsclass}'.format(rdsclass=rdsv['class']) # TOOD : constante !!

    # Check iops rules http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Storage.html#USER_PIOPS
    if rdsv['storage-type'] == 'io1':
        if not rdsv.get('iops', False):
            fatal("RDS : When storage-type is io1 you need to set IOPS")
        if rdsv['engine']:
            if not (float(rdsv['iops']) / float(rdsv['size'])) >= 3.00 or not (float(rdsv['iops']) / float(rdsv['size'])) <= 10.00:
                fatal("RDS : When storage-type is io1 on {engine}, IOPS/size must be greater than 3 and less than 10").format(engine=rdsv['engine'])
        if rdsv['iops'] > 30000 or rdsv['iops'] < 1000:
            fatal("RDS : IOPS value must be set between 1000 and 30000")
        if rdsv['iops'] > 20000 and rdsv['engine'].startswith('sqlserver'):
            fatal("RDS : IOPS value must be set between 1000 and 20000 on SQL-Server")
        if rdsv['size'] < 100 or rdsv['size'] > 6000000:
            fatal("RDS : Size, when using io1, must be between 100Go and 6To")
        if rdsv['engine'].startswith('sqlserver') and rdsv['size'] < 100 or rdsv['size'] > 4000000:
            fatal("RDS : Size, when using io1, must be between 100Go and 4To on sqlserver")
    if rdsv['storage-type'] != 'io1' and rdsv.get('iops', False):
        fatal("RDS : When storage-type is not io1 you must not set iops")

    rds_dict = {}
    # Optional params
    if rdsv.get('publicly-accessible', 'pouet') != 'pouet':
        rds_dict['PubliclyAccessible'] = rdsv['publicly-accessible']
    if rdsv.get('license-model', False):
        rds_dict['LicenseModel'] = rdsv['license-model']
    if rdsv['storage-type'] == 'io1':
        rds_dict['Iops'] = rdsv['iops']
    if rdsv.get('option-group-name', False):
        rds_dict['OptionGroupName'] = rdsv['option-group-name']
    if rdsv.get('snapshot_id', False):
        rds_dict['DBSnapshotIdentifier'] = rdsv['snapshot_id']
    if rdsv.get('az', False):
        rds_dict['AvailabilityZone'] = REGION+rdsv['az']

    # Needed params
    rds_dict['MultiAZ'] = rdsv['multiAZ']
    rds_dict['AllocatedStorage'] = rdsv['size']
    rds_dict['AllowMajorVersionUpgrade'] = rdsv.get('allow-major-version-upgrade', False)
    rds_dict['AutoMinorVersionUpgrade'] = rdsv.get('auto-minor-version-upgrade', True)
    rds_dict['BackupRetentionPeriod'] = rdsv.get('backup-retention-period', 7)
    rds_dict['DBInstanceClass'] = rdsv['class']
    rds_dict['DBInstanceIdentifier'] = rdsk
    rds_dict['Engine'] = rdsv['engine']
    rds_dict['EngineVersion'] = fullversion
    rds_dict['MasterUsername'] = rdsv['master-user']
    rds_dict['MasterUserPassword'] = rdsv['master-password']
    if not rdsv.get('snapshot_id', False):
        rds_dict['DBName'] = rdsv['dbname']
    rds_dict['VPCSecurityGroups'] = []
    rds_dict['DBParameterGroupName'] = Ref(resourceName+'pg')
    rds_dict['DBSubnetGroupName'] = Ref(sng)
    rds_dict['StorageType'] = rdsv['storage-type']
    rds_dict['Tags'] = Tags(
        client=rdsFacts['client_code'],
        project=rdsFacts['project_code'],
        schedule=cur_schedule,
        environment=rdsFacts['platform']
    )

    rds_instance = t.add_resource(rds.DBInstance.from_dict(resourceName, rds_dict))

    for securityGroup in rdsv['security-groups']:
        if securityGroup.startswith('sg-'):
            rds_instance.VPCSecurityGroups.append(securityGroup)
        else:
            rds_instance.VPCSecurityGroups.append(GetAtt('StackSecurityGroup', 'Outputs.'+make_resource_name(securityGroup+'Id')))
    # Clear
    del rdsFacts


# ##############################################################################
# Elasticache
# ##############################################################################
for cachek, cachev in CACHES.items():
    engine = cachev.get('engine', '')
    if engine not in ['memcached', 'redis']:
        fatal('Type de cache "{engine}" inconnu pour cache "{name}"').format(engine=engine, cache=cachek)

    resourceName = make_resource_name(cachek)
    sng = t.add_resource(elasticache.SubnetGroup(
        resourceName+'ecsng',
        Description='subnet group for elasticache {name}'.format(name=resourceName),
        SubnetIds=[]
        )
    )

    for subnet in cachev['subnets']:
        if subnet.startswith('subnet-'):
            sng.SubnetIds.append(subnet)
        else:
            sng.SubnetIds.append(GetAtt('StackSubnet', 'Outputs.'+make_resource_name(subnet+'Id')))

    AutoMinorVersionUpgrade = cachev['autoUpgrade'] if cachev.get('autoUpgrade') else True
    AZMode = cachev['azMode'] if cachev.get('azMode') else 'cross-az'

    cache = t.add_resource(elasticache.CacheCluster(
        resourceName,
        AutoMinorVersionUpgrade=AutoMinorVersionUpgrade,
        CacheNodeType=cachev['nodeType'],
        Engine=engine,
        NumCacheNodes=cachev['nodes'],
        Port=cachev['port'],
        CacheSubnetGroupName=Ref(sng),
        VpcSecurityGroupIds=[],
        AZMode=AZMode
        )
    )
    for securityGroup in cachev['security-groups']:
        if securityGroup.startswith('sg-'):
            cache.VpcSecurityGroupIds.append(securityGroup)
        else:
            cache.VpcSecurityGroupIds.append(GetAtt('StackSecurityGroup', 'Outputs.'+make_resource_name(securityGroup+'Id')))

# Todo : ParameterGroup : http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html
# Todo : Why 1 for 1 SubnetGroup : http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html

# ##############################################################################
# SQS
# ##############################################################################
for sqsk, sqsv in SQSS.items():
    resourceName = make_resource_name(sqsk)
    sqs_dict = {}
    if sqsv.get('delay-seconds', False):
        sqs_dict['DelaySeconds'] = sqsv['delay-seconds']
    if sqsv.get('maximum-message-size', False):
        sqs_dict['MaximumMessageSize'] = sqsv['maximum-message-size']
    if sqsv.get('message-retention-period', False):
        sqs_dict['MessageRetentionPeriod'] = sqsv['message-retention-period']
    if sqsv.get('queue-name', False):
        sqs_dict['QueueName'] = sqsv['queue-name']
    if sqsv.get('receive-message-wait-time-seconds', False):
        sqs_dict['ReceiveMessageWaitTimeSeconds'] = sqsv['receive-message-wait-time-seconds']
    if sqsv.get('redrive-policy', False):
        sqs_dict['RedrivePolicy'] = sqsv['redrive-policy']
    if sqsv.get('visibility-timeout', False):
        sqs_dict['VisibilityTimeout'] = sqsv['visibility-timeout']

    sqs_instance = sqs.Queue.from_dict(resourceName, sqs_dict)
    t.add_resource(sqs_instance)


# ##############################################################################
# CloudFront
# ##############################################################################
# TOOD : et les autres !
priceClasses = {'US & Europe' : 'PriceClass_100'}

for cfk, cfv in CLOUDFRONTS.items():
    cname = cfv.get('cname') # TOOD : list of aliases
    priceClass = cfv.get('price-class')
    if priceClass not in priceClasses:
        fatal('Price-class "{priceClass}" inconnu pour cloudfront "{cloudfront}"').format(priceClass=priceClass, cloudfront=cfk)
    priceClass = priceClasses[priceClass]
    resourceName = make_resource_name(cfk)
    distribution = t.add_resource(cloudfront.Distribution(
        resourceName,
        DistributionConfig=cloudfront.DistributionConfig(
            Aliases=[cname],
            CacheBehaviors=[],
            Origins=[],
            Enabled=True,
            PriceClass=priceClass)))
    hasDefault = False
    for origink, originv in cfv.get('origins').items():
        if originv.get('default') == True:
            if hasDefault:
                fatal("Impossible de declarer plusieurs origines comme defaut, mec ! (je parle de CloudFront). {origin} est une origine de trop...").format(origin=origink)
            hasDefault = True
    if not hasDefault:
        fatal("Il faut tout de meme declarer une origine par defaut bon sang ! (je parle de CloudFront)")

    for origink, originv in cfv.get('origins').items():
        otype = originv.get('type') # TOOD : check values
        fqdn = originv.get('fqdn')
        allowedMethods = originv.get('methods').split(',')  # idem
        forwardQueryString = originv.get('forward-query-string') # TOOD : default & check
        forwardedCookies = originv.get('forwarded-cookies') # idem
        isDefault = originv.get('default', False) # TOOD : check no default !
        pathPattern = originv.get('path', None)
        oid = make_resource_name(origink)
        if otype == 's3':
            origin = cloudfront.Origin(
                Id=oid,
                DomainName=fqdn,
                S3OriginConfig=cloudfront.S3Origin()
            )
            if isDefault:
                distribution.DistributionConfig.DefaultCacheBehavior = cloudfront.DefaultCacheBehavior(
                    TargetOriginId=oid,
                    AllowedMethods=allowedMethods,
                    ForwardedValues=cloudfront.ForwardedValues(
                        Cookies=cloudfront.Cookies(
                            Forward=forwardedCookies
                        ),
    #                   Headers=, # TOOD => UserLanguage surement...
                        QueryString=forwardQueryString),
                    ViewerProtocolPolicy='allow-all' # TOOD : pas bon, je sais...
                ) # TOOD : MinTTL
            else:
                distribution.DistributionConfig.CacheBehaviors.append(cloudfront.CacheBehavior(
                    TargetOriginId=oid,
                    AllowedMethods=allowedMethods,
                    PathPattern=pathPattern,
                    ForwardedValues=cloudfront.ForwardedValues(
                        Cookies=cloudfront.Cookies(
                            Forward=forwardedCookies
                        ),
    #                   Headers=, # TOOD => UserLanguage surement...
                        QueryString=forwardQueryString
                    ),
                    ViewerProtocolPolicy='allow-all' # TOOD : pas bon, je sais...
                )) # TOOD : MinTTL
        else:
            origin = cloudfront.Origin(
                Id=oid,
                DomainName=fqdn,
                CustomOriginConfig=cloudfront.CustomOrigin(
                    OriginProtocolPolicy='match-viewer')
            )
            if isDefault:
                distribution.DistributionConfig.DefaultCacheBehavior = cloudfront.DefaultCacheBehavior(  # TOOD : factorisation CacheBehavior
                    TargetOriginId=oid,
                    AllowedMethods=allowedMethods,
                    ForwardedValues=cloudfront.ForwardedValues(
                        Cookies=cloudfront.Cookies(
                            Forward=forwardedCookies
                        ),
    #                   Headers=, # TOOD => UserLanguage surement...
                        QueryString=forwardQueryString
                    ),
                    ViewerProtocolPolicy='allow-all' # TOOD : pas bon, je sais...
                ) # TOOD : MinTTL
            else:
                distribution.DistributionConfig.CacheBehaviors.append(cloudfront.CacheBehavior(  # TOOD : factorisation CacheBehavior
                    TargetOriginId=oid,
                    AllowedMethods=allowedMethods,
                    PathPattern=pathPattern,
                    ForwardedValues=cloudfront.ForwardedValues(
                        Cookies=cloudfront.Cookies(
                            Forward=forwardedCookies
                        ),
    #                   Headers=, # TOOD => UserLanguage surement...
                        QueryString=forwardQueryString
                    ),
                    ViewerProtocolPolicy='allow-all' # TOOD : pas bon, je sais...
                )) # TOOD : MinTTL
        distribution.DistributionConfig.Origins.append(origin)

# ##############################################################################
# Include Nested Stack
# ##############################################################################
if 'StackSecurityGroup' in nested_stack:
    STACK_SG['TemplateURL'] = Join('/', [Ref(s3_bucket_url), os.path.basename(TEMPLATEFILE_SG)])
    STACK_SG['Parameters']['TheVPC'] = vpc_id
    STACK_SG['TimeoutInMinutes'] = 60
    stack_sg = t.add_resource(cloudformation.Stack.from_dict('StackSecurityGroup', STACK_SG))
    for param in STACK_SG['Parameters']:
        t_sg.add_parameter(Parameter(
           param,
           Type='String'))

if 'StackSubnet' in nested_stack:
    STACK_SNET['TemplateURL'] = Join('/', [Ref(s3_bucket_url), os.path.basename(TEMPLATEFILE_SNET)])
    STACK_SNET['Parameters']['TheVPC'] = vpc_id
    STACK_SNET['Parameters']['InternetGateway'] = igw
    STACK_SNET['TimeoutInMinutes'] = 60
    stack_subnet = t.add_resource(cloudformation.Stack.from_dict('StackSubnet', STACK_SNET))
    for param in STACK_SNET['Parameters']:
        t_snet.add_parameter(Parameter(
           param,
           Type='String'))

for resourceName, route_instance in routeInstances.iteritems():
    #route_instance['DependsOn'] = Ref(stack_subnet)
    route_instance['RouteTableId'] = GetAtt('StackSubnet', 'Outputs.'+route_instance['RouteTableId'])
    t.add_resource(ec2.Route.from_dict(resourceName, route_instance))

# ##############################################################################
# ECRITURE...
# ##############################################################################
content = t.to_json()
content_sg = t_sg.to_json()
content_snet = t_snet.to_json()

if TEMPLATEFILE:
    with open(TEMPLATEFILE, 'w') as out:
        out.write(content)
    print('template written to {target}').format(target=TEMPLATEFILE)
else:
    print content

if TEMPLATEFILE_SG:
    with open(TEMPLATEFILE_SG, 'w') as out:
        out.write(content_sg)
    print('template written to {target}').format(target=TEMPLATEFILE_SG)
else:
    print content_sg

if TEMPLATEFILE_SNET:
    with open(TEMPLATEFILE_SNET, 'w') as out:
        out.write(content_snet)
    print('template written to {target}').format(target=TEMPLATEFILE_SNET)
else:
    print content_snet

