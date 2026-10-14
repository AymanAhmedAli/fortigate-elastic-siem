# FortiGate Syslog Configuration

Current device: FortiGate-VM64, FortiOS 7.6.7 build3704. See [current addressing](../README.md#architecture). Collector: Ubuntu `10.10.10.20` on port2/internal LAN.

## CLI Configuration

config log syslogd setting
set status enable
set mode udp
set server "10.10.10.20"
set port 5144
set facility local7
set format default
end


## Verify
Check logs arriving in Kibana under FortiGate Logs data view.
