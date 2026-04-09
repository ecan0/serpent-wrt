# Wazuh Integration for serpent-wrt

Decoder and rules for ingesting serpent-wrt NDJSON alerts via syslog into Wazuh.

## Install

1. Copy the decoder and rules to the Wazuh manager:

```sh
cp decoder-serpent-wrt.xml /var/ossec/etc/decoders/
cp rules-serpent-wrt.xml /var/ossec/etc/rules/
```

2. Configure Wazuh to accept syslog from the router. In `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.0.0/16</allowed-ips>
  <local_ip><YOUR-WAZUH-IP></local_ip>
</remote>
```

3. Restart the Wazuh manager:

```sh
systemctl restart wazuh-manager
```

4. Configure serpent-wrt to forward syslog in `serpent-wrt.yaml`:

```yaml
syslog_target: "<YOUR-WAZUH-IP>:514"
syslog_proto: "udp"
```

## Alert Levels

| Rule ID | Detector | Level | MITRE ATT&CK | Description |
|---------|----------|-------|---------------|-------------|
| 100200 | (any) | 3 | — | Base detection event |
| 100201 | enforcer | 6 | — | IP blocked via nftables |
| 100202 | feed_match | 10 | T1071 Application Layer Protocol | Traffic to/from known threat intel IP |
| 100203 | fanout | 8 | T1018 Remote System Discovery | Internal host contacting many external destinations |
| 100204 | port_scan | 8 | T1046 Network Service Scanning | Internal host scanning ports on external target |
| 100205 | beacon | 9 | T1071.001 Web Protocols (C2) | Periodic beaconing to external destination |
| 100206 | ext_scan | 7 | T1046 Network Service Scanning | External IP scanning ports on internal host |
| 100207 | brute_force | 8 | T1110 Brute Force | External IP hitting same port across many internal hosts |

## Verification

Trigger a test detection (e.g. a feed_match) and check Wazuh alerts:

```sh
grep "serpent-wrt" /var/ossec/logs/alerts/alerts.log | tail -5
```

Or query via the Wazuh API / dashboard for rule group `serpent-wrt`.
