# Snort Ubuntu Server 22.04 
## Required
```
apt-get install -y build-essential
apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev -y
apt-get install -y bison flex -y
apt-get install -y zlib1g-dev liblzma-dev openssl libssl-dev -y
apt-get install libnghttp2-dev
```
## Install
```
mkdir /snort
cd /snort
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -zxf daq-2.0.7.tar.gz
tar -zxf snort-2.9.20.tar.gz
cd daq-2.0.7
./configure
make
make install
```
```
cd /snort
git clone https://github.com/lattera/glibc.git
cp -r /snort/glibc/sunrpc/rpc/* /usr/include/rpc
```
```
cd /snort/snort-2.9.20
./configure --enable-sourcefire --disable-open-appid
make
make install
```
```
ldconfig

ln /usr/local/bin/snort /usr/sbin/snort

snort -V
```
## Create configuration folder
```
mkdir /etc/snort
mkdir /etc/snort/rules
mkdir /etc/snort/rules/iplists
mkdir /etc/snort/preproc_rules
mkdir /usr/local/lib/snort_dynamicrules
mkdir /etc/snort/so_rules
```
## Create rules file 
```
touch /etc/snort/rules/iplists/black_list.rules
touch /etc/snort/rules/iplists/white_list.rules
touch /etc/snort/rules/local.rules
touch /etc/snort/sid-msg.map
#Tạo thư mục chứa log:
mkdir /var/log/snort
mkdir /var/log/snort/archived_logs
```
## Copy backup file
```
cd /snort/snort-2.9.20/etc

cp *.conf* /etc/snort
cp *.map /etc/snort
cp *.dtd /etc/snort
cd /snort/snort2.9.20//src/dynamicpreprocessors/build/usr/local/lib/snort_dynamicpreprocessor/
sudo cp * /usr/local/lib/snort_dynamicpreprocessor/
```
## Config
```
sudo nano /etc/snort/snort.conf

ipvar HOME_NET 10.0.0.0/24
ipvar EXTERNAL_NET !$HOME_NET (Line 48)

var RULE_PATH /etc/snort/rules (Line 104)
var SO_RULE_PATH /etc/snort/so_rules (Line 105)
var PREPROC_RULE_PATH /etc/snort/preproc_rules (Line 106)
var WHITE_LIST_PATH /etc/snort/iplists (Line 113)
var BLACK_LIST_PATH /etc/snort/iplists (Line 114)

Path to rule file
include $RULE_PATH/local.rules (Line 546)


sudo sed -i "s/include \$RULE\_PATH/#include \$RULE\_PATH/" /etc/snort/snort.conf

snort -i ens33 -c /etc/snort/snort.conf -T 

```
## Rule
```
alert icmp any any -> any any (msg:"Nmap ICMP scaning";\
sid:10000001; rev:1;)
```
```
alert tcp any any -> $HOME_NET any (msg:"SYN scan attack";\
detection_filter:track by_src, count 100, seconds 2; flags:S;\
classtype:network-scan; sid:10000002; rev:1;)
```
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping of Death";itype:8; dsize:>1000; detection_filter:track by_src, count 10, seconds 5; classtype:denial-of-service; sid:10000003; rev:1;)```
