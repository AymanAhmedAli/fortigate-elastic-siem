# FortiGate Syslog Configuration

## CLI Configuration

config log syslogd setting
set status enable
set server "YOUR_ELASTIC_IP"
set port 5144
set facility local7
set format default
end


## Verify
Check logs arriving in Kibana under FortiGate Logs data view.
