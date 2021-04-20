# 5G Trace Anaylzer

## What is 5G Sequence Analyzer?
The 5G Sequence Analyzer is an open-source project to process and analyze 5G network traces.
The initial trance files(.pcap) are originated from free5GC project.

## How to install?

Install VirtualBox and Vagrant:
VirtualBox: https://www.virtualbox.org/wiki/Linux_Downloads

Vagrant:    https://www.vagrantup.com/docs/installation

### Vagrant Config
Copy below config in a file named `Vagrantfile`
```
Vagrant.configure("2") do |config|
  config.vm.define "fiveGTraceAnalyzer"
  
  
  config.vm.provider "virtualbox" do |vb|
	config.vm.network "private_network", ip: "192.168.56.4", :adapter => 2
    vb.memory = 2048
    vb.cpus = 2
  end
  
  config.vm.hostname = "master"
  config.vm.box = "ubuntu/bionic64"
  config.vm.synced_folder "shared", "/vagrant", disabled: false

end
```

:zero: Install a ubuntu machine using Vagrant
```
vagrant plugin install vagrant-reload
vagrant up
```

### Direct Installation (Linux Installation :: Ubuntu)
:one: Install mongodb, wget and git
```
sudo apt-get -y update
sudo apt-get -y install mongodb wget git
sudo systemctl enable mongodb
```

:two: Install wireshark, T-shark & java
```
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
sudo apt-get -y install software-properties-common
sudo add-apt-repository ppa:wireshark-dev/stable -y
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark
sudo apt-get -y install default-jre

sudo apt-get clean
```

3️⃣ Change directory & Clone the project
```
cd ~
git clone https://github.com/SadeghKrmi/5G-Trace-Analyzer.git
```

4️⃣ Install python3 libs and dependencies for django
```
cd ~/5G-Trace-Analyzer/
sudo apt-get -y install python3-pip
sudo pip3 install virtualenv
sudo virtualenv .env
source .env/bin/activate
sudo .env/bin/pip3 install -r  requirements.txt
```

5️⃣ Install requirement on python base
```
cd ~/5G-Trace-Analyzer/
sudo pip3 install -r requirements.txt
```

6️⃣ Load protocol settings into database
```
cd ~/5G-Trace-Analyzer/
sudo apt-get install -y mongo-tools
mongorestore -d 'diagram' preconfig/db_dump/diagram/
```

:seven: Run the django server
```
cd ~/5G-Trace-Analyzer/fiveGseqAnalyzer
sudo ../.env/bin/python3 manage.py runserver 0.0.0.0:8080
```

Browse address yourmachineIP:8080 in your browser:

Ex: http://192.168.56.4:8080

### Login Credientials
```text
user: testuser
pass: trace@123
```
