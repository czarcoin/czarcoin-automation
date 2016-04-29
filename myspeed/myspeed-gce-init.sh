#!/bin/bash

apt-get update
apt-get install -y git htop
useradd -m -d /opt/storj storj
sudo su - storj -c "curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.31.0/install.sh | bash"
sudo su - storj -c "source ~/.nvm/nvm.sh && nvm install stable && nvm use stable && nvm alias default stable"
sudo su - storj -c "source ~/.nvm/nvm.sh && git clone https://github.com/gordonwritescode/myspeed.git && cd myspeed && npm install"
mkdir /var/log/storj
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt-get install -y iptables-persistent
chown storj:storj /var/log/storj
wget -P /etc/init https://github.com/storj/storj-automation/raw/master/myspeed/init/myspeed.conf
service myspeed start
