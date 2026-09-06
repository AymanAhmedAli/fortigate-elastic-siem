## Project Overview

As an IT Specialist at NAWY managing enterprise infrastructure across 3 office locations, I needed a centralized security monitoring solution to aggregate and analyze logs from multiple sources in real-time.

This project documents how I built a complete SIEM (Security Information and Event Management) system from scratch using open-source tools, integrating FortiGate firewall logs, Active Directory events, and Windows endpoint logs into a single Kibana dashboard.

---

## The Problem

Before this project, our security monitoring was fragmented:
- FortiGate firewall logs were only viewable locally on each device
- Windows AD authentication events had no centralized visibility
- No way to correlate events across different systems
- No real-time alerting on suspicious activity

---

## Architecture

```
FortiGate Firewall
    ↓ Syslog (UDP 5144)
Logstash (parsing & processing)
    ↓
Elasticsearch (storage & indexing)
    ↓
Kibana (visualization & dashboards)

Windows Server 2022 (Active Directory)
    ↓ Winlogbeat
Elasticsearch → Kibana

Windows Client (Domain-joined)
    ↓ Winlogbeat (deployed via GPO)
Elasticsearch → Kibana
```

---

## Tech Stack

| Component | Version | Role |
|-----------|---------|------|
| FortiGate | v7.0.5 | Firewall & log source |
| Elasticsearch | 8.19.21 | Log storage & indexing |
| Logstash | 8.19.21 | Log collection & parsing |
| Kibana | 8.19.21 | Visualization & dashboards |
| Winlogbeat | 8.19.21 | Windows event log shipper |
| Windows Server 2022 | — | Active Directory + DC |
| Ubuntu 24.04 | — | ELK Stack host |

---

## Setup Process

### 1. Elastic Stack Installation (Ubuntu)

Installed Elasticsearch, Kibana, and Logstash from official Elastic repositories.

Key configuration changes:
- Set `network.host: 0.0.0.0` to allow external connections
- Configured `kibana_system` user credentials
- Set `server.host: 0.0.0.0` in Kibana for remote access

### 2. FortiGate Syslog Configuration

Configured FortiGate to send logs via Syslog to Logstash:

```
config log syslogd setting
    set status enable
    set server "172.18.183.113"
    set port 5144
    set facility local7
    set format default
end
```

### 3. Logstash Pipeline (FortiGate)

Created a pipeline to receive, parse, and forward FortiGate logs:

```
input {
  udp {
    port => 5144
    type => "fortigate"
  }
}
filter {
  grok {
    match => { "message" => "%{SYSLOG5424PRI}%{GREEDYDATA:log_message}" }
  }
}
output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "..."
    ssl_certificate_verification => false
    index => "fortigate-logs-%{+YYYY.MM.dd}"
  }
}
```

### 4. Winlogbeat — Active Directory

Installed Winlogbeat on Windows Server 2022 (Domain Controller) to ship Windows Event Logs to Elasticsearch.

### 5. GPO Deployment — Windows Clients

Instead of manually installing Winlogbeat on each client, I used Group Policy to automate deployment:

1. Created shared folder `\\DC\Winlogbeat-Deploy`
2. Added Winlogbeat files + deploy script
3. Created GPO with Startup Script pointing to deploy.ps1
4. GPO auto-installs and starts Winlogbeat on domain-joined machines

This is the production-grade approach — any new machine joining the domain automatically gets Winlogbeat installed.

---

## Results

- ✅ FortiGate firewall logs streaming in real-time to Kibana
- ✅ Windows AD authentication events captured (login, logout, failed attempts)
- ✅ Windows Client events captured via GPO deployment
- ✅ 755+ security events collected and indexed
- ✅ Centralized visibility across all sources in one dashboard

---

## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| Elasticsearch SSL certificate mismatch after IP change | Changed `network.host` and updated Kibana credentials |
| Kibana not connecting to Elasticsearch | Reset `kibana_system` password via CLI |
| GPO script not running on client | Enabled File and Printer Sharing on DC firewall |
| Winlogbeat ExecutionPolicy error | Set `ExecutionPolicy Bypass` in deploy script |

---

## Key Learnings

1. **Integration is the hard part** — Installing tools is easy. Making them talk to each other is where real engineering happens.

2. **GPO for scale** — Manual installation doesn't scale. GPO-based deployment means zero-touch installation for all future machines.

3. **Network configuration matters** — Changing IPs broke SSL certificates and Kibana connections. Always plan your network topology before deployment.

4. **Security by default** — Elasticsearch 8.x has SSL/TLS enabled by default. This is good for security but adds complexity to integrations.

---

## Repository Structure

```
fortigate-elastic-siem/
├── configs/
│   └── fortigate.conf      # Logstash pipeline config
├── setup/
│   ├── elasticsearch.md    # Installation guide
│   ├── kibana.md           # Setup guide
│   ├── logstash.md         # Configuration guide
│   └── fortigate.md        # FortiGate syslog config
├── screenshots/
│   ├── architecture_diagram.png
│   ├── kibana_fortigate_logs.png
│   ├── kibana_dc_logs.png
│   └── kibana_dc_client_logs.png
└── README.md
```

---

## Next Steps

- [ ] Add Kaspersky Security Center integration
- [ ] Build custom Kibana dashboards
- [ ] Configure alerts for suspicious events (failed logins, port scans)
- [ ] Integrate 3 production FortiGate firewalls
- [ ] Add Docker/Kubernetes deployment option

---

*Built by Ayman Ahmed — IT Specialist | Network Security*
*[GitHub](https://github.com/AymanAhmedAli) | [LinkedIn](https://www.linkedin.com/in/aymanahmedali/)*
EOF
echo "Done!"
