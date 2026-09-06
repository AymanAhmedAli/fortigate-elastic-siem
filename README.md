# 🔐 FortiGate + Elastic Stack SIEM Integration

Real-time security monitoring by integrating FortiGate firewall logs with Elastic Stack (Elasticsearch + Kibana + Logstash).

## 🏗️ Architecture

![SIEM Architecture](screenshots/architecture_diagram.png)
↓ Syslog (UDP 5144)
Logstash
↓
Elasticsearch
↓
Kibana Dashboard


## 🛠️ Stack
- **FortiGate** v7.0.5 — Firewall & log source
- **Elasticsearch** 8.19 — Log storage & indexing
- **Logstash** 8.19 — Log collection & parsing
- **Kibana** 8.19 — Visualization & dashboards

## 📂 Contents
- [Elasticsearch Setup](setup/elasticsearch.md)
- [Kibana Setup](setup/kibana.md)
- [Logstash Setup](setup/logstash.md)
- [FortiGate Config](setup/fortigate.md)
- [Logstash Config](configs/fortigate.conf)

## 👤 Author
**Ayman Ahmed** — IT Specialist | Network Security
[GitHub](https://github.com/AymanAhmedAli) | [LinkedIn](https://www.linkedin.com/in/aymanahmedali/)
