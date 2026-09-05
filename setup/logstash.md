# Logstash Setup

## Installation
```bash
sudo apt install logstash -y
```

## FortiGate Config
Copy fortigate.conf to /etc/logstash/conf.d/

## Start Service
```bash
sudo systemctl enable logstash
sudo systemctl start logstash
```
