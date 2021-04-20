# 5G Trace Anaylzer

## What is 5G Sequence Analyzer (fiveGSeqAnalyzer)?
The 5G Sequence Analyzer is an open-source project to process and analyze 5G network traces.
The initial trance files(.pcap) are originated from free5GC project.

## How to install?
### Direct Installation
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
git https://github.com/SadeghKrmi/5G-Trace-Analyzer.git
```

4️⃣ Install python3 libs and dependencies for django
```
cd ~/fivegsequenceanalyzer/
sudo apt-get -y install python3-pip
sudo pip3 install virtualenv
sudo virtualenv .env
source .env/bin/activate
sudo .env/bin/pip3 install -r  preconfig/requirements.txt
```

5️⃣ Install requirement on python base
```
cd ~/fivegsequenceanalyzer/
sudo pip3 install -r preconfig/requirements.txt
```

6️⃣ Load protocol settings into database
```
cd ~/fivegsequenceanalyzer/
sudo apt-get install -y mongo-tools
mongorestore -d 'diagram' preconfig/db_dump/diagram/
``
