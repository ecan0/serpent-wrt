# Wazuh Integration for serpent-wrt

Decoder and rules for serpent-wrt NDJSON alerts that arrive through syslog.

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
| 100200 | (any) | 3 | — | Base event |
| 100201 | detection | 10 | — | Any detection event |
| 100202 | feed_match | 12 | T1071 Application Layer Protocol | Traffic to/from known threat intel IP |
| 100203 | port_scan | 10 | T1046 Network Service Scanning | Internal host scanning ports on external target |
| 100204 | fanout | 10 | T1018 Remote System Discovery | Internal host contacting many external destinations |
| 100205 | beacon | 10 | T1071.001 Web Protocols (C2) | Periodic beaconing to external destination |
| 100206 | ext_scan | 10 | T1046 Network Service Scanning | External IP scanning ports on internal host |
| 100207 | brute_force | 10 | T1110 Brute Force | External IP hitting same port across many internal hosts |
| 100210 | enforcer | 10 | — | IP added to the configured nftables timed set |


## NAT tuple fields

`dst_ip` and `dst_port` retain the original conntrack destination.
For DNAT snapshots, `translated_dst_ip` and `translated_dst_port` report the internal endpoint.
The JSON decoder exposes both endpoint pairs to Wazuh alerts and index searches.

When `event_context` is set, detection alerts retain `run_id` and `case_id`.

## Scan Episode Fields

`port_scan` and `ext_scan` alerts include `distinct_port_count` and a sorted `observed_dst_ports` array.
Each alert describes one threshold episode.

## Verification

Trigger a test detection (e.g. a feed_match) and check Wazuh alerts:

```sh
grep "serpent-wrt" /var/ossec/logs/alerts/alerts.log | tail -5
```

Or query via the Wazuh API / dashboard for rule group `serpent-wrt`.
