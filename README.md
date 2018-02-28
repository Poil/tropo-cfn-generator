## CL@WS

### Main Config
* required parameters
    * account_id : Account Number
    * s3bucket : Bucket to store Cloudformation Templates
    * keypair : Keypair name
    * region : Region (eu-west-1, ap-southeast-1, ...)
    * defaultAZ : Default Availibility Zone (a, b, c)
    * facts: Fact hash list for Puppet management and instance tagging
    * amis: Mapping of AMI Name / AMI ID
    * domain : domain name to autoregister
    * zone : subdomain (without domain name)
* optional parameters
    * vpc : VPC ID if deploy in an existant VPC
    * vgw : Virtual Gateway ID
    * r53_hosted_zone : route53 zone to auto register instance at boot
    * prefix : Prefix for resource name
    * dns : custom resolver
* inclusion :  Listing of included configuration

### VPC
* cidr

### ROUTE53
* zone
    * type : private or public
    * main: true/false (Is the zone will be used for dhcp option set)
    * vpc: List of external VPC which will be able to query the private zone

### Security Group
* securitygroup resource name
    * desc: Description
    * in: List of incoming "proto:port:cidr"
        * proto : tcp/udp/icmp
        * port : a port or a range "from-to" or a comma separated list of port 
        * cidr : a cidr or a comma separated list of cidr
    * out : List of outgoing "proto:port:cidr"
        * proto : tcp/udp/icmp
        * port : a port or a range "from-to" or a comma separated list of port 
        * cidr : a cidr or a comma separated list of cidr
    
### Route Tables
* routetable resource name
    * propagation : true/false
    * routes: array of hashes "to: cidr", "via: "cidr" or instance resource name or other resource name (pcx-XXXXXX) or "internet-gateway"

### Subnets
* subnet resource name
    * cidr: The cidr
    * az: The availability zone (a, b, c)
    * rt: the route table resource name associated with this subnet

### Instances (EC2)
* yaml object name
    * name : resource name
    * hostname : Hostname
    * ami : AMI name
    * instanceType : The instance Type
    * os_type : linux/windows
    * subnetId : subnet resource name
    * az : Availability Zone (must be in the same AZ as the subnet)
    * ebsSize : Size of the 2nd EBS volume
    * root_size : Size of the main EBS volume (default value is 15)
    * enabled : True/False, if set to False will remove the instance
    * public : True/False, if set to True will assign an EIP (yes static one)
    * availability : Manage the power state of the instance  via this tag
        * non-business-hours : Always on
        * never : Always off
        * business-hours/9-20 : On from 9hr to 20hr
    * security-groups : List of securitygroup resource name
    * sourceDestCheck: true/false if instance is a NAT instance set it to false
    * user-metadata : filename of the user-metadata template
    * cloudformation-init : filename of the cloudformation-init template

### AutoScaling Group
* yaml object name
    * name : resource name
    * desired-capacity : integer
    * minsize : integer
    * maxsize : integer
    * cooldown : integer or False
    * launch-configuration : resource name of the launch-configuration
    * subnet : List of subnet resource name
    * az : List of AZ (a, b, c)
    * healthchecktype : EC2 or ELB, default is EC2
    * loadbalancers : List of attached loadbalancer resource name (if needed)

### Launch Configuration
* yaml object name
    * name: resource name
    * ami : AMI name
    * instanceType : The instance Type
    * os_type : linux/windows
    * ebsSize : Size of the 2nd EBS volume
    * root_size : Size of the main EBS volume (default value is 15)
    * enabled : True/False, if set to False will remove the instance
    * policies: hashes of policies (see policies)
    * user-metadata : filename of the user-metadata template
    * cloudformation-init : filename of the cloudformation-init template
    * facts : hash of facts

### S3
* resource name
    * access_control : Public/Private
    * policies : Hash of policies

### ELBs
* resource name
    * health-protocol : TCP/HTTP
    * health-port : integer
    * listeners : list of listener TCP:80, HTTP:80
    * public : True/False
    * crosszone : True/False
    * proxy-protocol : True/False
    * proxy-protocol-ports : integer
    * security-groups : List of security group resource name
    * subnets : List of subnet resource name
    * instances : List of instance resource name
    * accesslogging : 
        * bucket : s3 bucket resource name

### RDS
* resource name
    * engine
    * version-major
    * version-minor
    * class
    * multiAZ
    * storage-type
    * size
    * security-groups
    * master-user
    * master-password
    * dbname
    * subnets
    * parameters
    * availability

### Elasticache
* resource name
    * nodeType
    * engine
    * nodes
    * port
    * security-groups
    * subnets

### SQS
* resource name
    * delay-seconds
    * maximum-message-size
    * message-retention-period
    * queue-name
    * receive-message-wait-time-seconds
    * redrive-policy
    * visibility-timeout

### CloudFront
* resource name
    * cname
    * price-class
    * origins
    * type
    * fqdn
    * methods
    * forward-query-string
    * forwarded-cookies
    * default
    * path

## Usage
* Generate the cloudformation template
```
make -f Makefile.vpccustomer makeCfn
```

* Generate and run the cloudformation template
```
make -f Makefile.vpccustomer deploy POLICY=update-all.template
```
