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
