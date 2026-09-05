# Kibana Setup

## Installation
```bash
sudo apt install kibana -y
```

## Configure
```bash
sudo nano /etc/kibana/kibana.yml
# Change: server.host: "0.0.0.0"
```

## Start Service
```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

## Access
http://172.25.31.6:5601


## Connect to Elasticsearch
Generate enrollment token:
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```
