#!/bin/bash -v

. /etc/profile.d/aws-apitools-common.sh
# Configure iptables
/sbin/iptables -t nat -A POSTROUTING -o eth0 -s 0.0.0.0/0 -j MASQUERADE
/sbin/iptables-save > /etc/sysconfig/iptables
# Configure ip forwarding and redirects
echo 1 >  /proc/sys/net/ipv4/ip_forward && echo 0 >  /proc/sys/net/ipv4/conf/eth0/send_redirects
mkdir -p /etc/sysctl.d/
cat <<EOF > /etc/sysctl.d/nat.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.eth0.send_redirects = 0
EOF
# Download nat_monitor.sh and configure
cd /root
wget http://media.amazonwebservices.com/articles/nat_monitor_files/nat_monitor.sh
# Wait for NAT #2 to boot up and update PrivateRouteTable2
sleep 180
NAT_ID=
# CloudFormation should have updated the PrivateRouteTable2 by now (due to yum update), however loop to make sure
while [[ -z "$NAT_ID" ]]; do
  sleep 60
  NAT_ID=$(aws ec2 describe-route-tables --route-table-ids=rtb-bff70fda --output=text | awk '/0.0.0.0\/0/ { print $3 }')
done
# Update NAT_ID, NAT_RT_ID, and My_RT_ID
sed -i -e "s/NAT_ID=/NAT_ID=${NAT_ID}/g" \
       -e "s/NAT_RT_ID=/NAT_RT_ID=#{PrivateRouteTable2}/g" \
       -e "s/My_RT_ID=/My_RT_ID=#{PrivateRouteTable1}/g" \
       -e "s/EC2_URL=/EC2_URL=https:\/\/ec2.#{AWS::Region}.amazonaws.com" \
       -e "s/Num_Pings=3/Num_Pings=#{NumberOfPings}/g" \
       -e "s/Ping_Timeout=1/Ping_Timeout=#{PingTimeout}/g" \
       -e "s/Wait_Between_Pings=2/Wait_Between_Pings=#{WaitBetweenPings}/g" \
       -e "s/Wait_for_Instance_Stop=60/Wait_for_Instance_Stop=#{WaitForInstanceStop}/g" \
       -e "s/Wait_for_Instance_Start=300/Wait_for_Instance_Start=#{WaitForInstanceStart}/g" /root/nat_monitor.sh

chmod a+x /root/nat_monitor.sh
echo '@reboot /root/nat_monitor.sh > /tmp/nat_monitor.log' | crontab
/root/nat_monitor.sh > /tmp/nat_monitor.log &

