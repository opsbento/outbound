# outbound

`outbound` monitors outgoing connections on Linux. In `audit` mode it logs destinations without blocking them. In `enforce` mode it blocks destinations outside the configured domain and CIDR allowlist.

It supports Linux `amd64` and `arm64` with systemd, cgroup v2, and a kernel that supports the required eBPF hooks (5.17 or newer). Start in `audit` mode on your target VM.

## Install on Ubuntu

Run these commands **on the VM**. Replace `VERSION` with a published [release](https://github.com/opsbento/outbound/releases) tag.

```sh
VERSION=vX.Y.Z  # replace with a published release tag
REPO=opsbento/outbound
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
ASSET="outbound-${VERSION}-linux-${ARCH}"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
curl -fL --retry 3 -O "${BASE}/${ASSET}"
DIGEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" | python3 -c 'import json,re,sys; name=sys.argv[1]; assets=[a for a in json.load(sys.stdin)["assets"] if a["name"]==name]; assert len(assets)==1 and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", assets[0]["digest"]); print(assets[0]["digest"].split(":",1)[1])' "$ASSET") || exit 1
printf '%s  %s\n' "$DIGEST" "$ASSET" | sha256sum --check || exit 1
RAW="https://raw.githubusercontent.com/${REPO}/${VERSION}/packaging"
for file in config.example.yaml outbound.service outbound.logrotate; do
  curl -fL --retry 3 -O "${RAW}/${file}" || exit 1
done
```

Review `config.example.yaml`, then install the downloaded files:

```sh
sudo groupadd --system --force outbound
id -u outbound >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid outbound outbound
sudo install -d -m 0755 /etc/outbound
sudo install -d -o outbound -g outbound -m 0750 /var/log/outbound
sudo install -m 0755 "$ASSET" /usr/local/bin/outbound
sudo install -m 0644 config.example.yaml /etc/outbound/config.yaml
sudo install -m 0644 outbound.service /etc/systemd/system/outbound.service
sudo install -m 0644 outbound.logrotate /etc/logrotate.d/outbound
sudo /usr/local/bin/outbound --check-config --config /etc/outbound/config.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now outbound
```

The included config starts in `audit` mode. The systemd unit prepares `/sys/fs/bpf/outbound` and runs the daemon as the `outbound` user.

## Configure

Edit `/etc/outbound/config.yaml`. This is a short example; see the [sample config](packaging/config.example.yaml) for more domains.

```yaml
version: "v1"
settings:
  mode: "audit"                 # change to "enforce" after checking the logs
  log_level: "info"
  log_file: "/var/log/outbound/outbound.log"
  dns_refresh_interval: "30s"
  max_ip_entries: 1024
  cover_all_udp: true
allowlist:
  domains:
    - "metadata.google.internal"
    - "*.ubuntu.com"
    - "*.googleapis.com"
    - "*.amazonaws.com"
  cidrs:
    - cidr: "127.0.0.53/32" # Ubuntu DNS stub; confirm /etc/resolv.conf
      ports: [53]
    - cidr: "10.10.10.10/32" # SSH allowed only to this IP
      ports: [22, 2222]
    - cidr: "10.10.10.20/32" # app port allowed only to this IP
      ports: [3000]
```

Exact domains are resolved at startup and refreshed periodically. Wildcards learn IPs from ordinary UDP DNS replies; `*.amazonaws.com` does not include `amazonaws.com` itself. Add it separately if needed. The final decision uses destination **IP**, so another service or proxy on an allowed IP can also be reached.

Each CIDR or domain may be a string (any port) or an object with `cidr`/`domain` and `ports` (up to 16 ports). For example, `- {domain: "*.example.com", ports: [1138, 2218]}` permits those ports on learned IPs. Exact-domain and CIDR rules for the same IP combine their ports; the most specific CIDR wins when CIDRs overlap. The hooks check TCP and UDP socket destinations on every port; loopback traffic stays within the host and is exempt. `cover_all_udp: true` is required. Allow the DNS resolver IP on port 53 before enforcing. DNS over HTTPS/TLS/TCP and cached DNS answers cannot teach wildcard IPs to the DNS hook.

After changing the config:

```sh
sudo /usr/local/bin/outbound --check-config --config /etc/outbound/config.yaml
sudo systemctl restart outbound
```

## Check status and logs

```sh
sudo systemctl status outbound --no-pager -l
sudo tail -f /var/log/outbound/outbound.log
sudo journalctl -u outbound -n 50 --no-pager
sudo /usr/local/bin/outbound --policy-status
```

The log file contains one JSON object per line. `destination_observed` records the decision, transport, destination IP and port, and a DNS-observed `domain` when available. `domain_source: dns_answer` means the name came from a recent DNS answer for that IP; it is not proof of the HTTP Host or TLS SNI. Shared IPs with multiple observed names, cached DNS, direct-IP connections, and encrypted DNS may leave `domain` empty. `policy_sha256` identifies the loaded config; compare it with `sha256sum /etc/outbound/config.yaml`. `ip_policy_sha256` on `service_started` and `ip_policy_changed` identifies the resolved exact-domain and CIDR map; it excludes IPs learned from wildcard DNS.

```sh
sudo tail -n 20 /var/log/outbound/outbound.log | jq -r 'select(.event == "destination_observed") | "\(.decision) \(.transport) \(.domain // .destination_ip):\(.destination_port)"'
sha256sum /etc/outbound/config.yaml
```

Destination logs are aggregated by eBPF per destination between one-second drains. At `log_level: info`, repeated ALLOW destinations are logged at most once every five minutes; BLOCK and WOULD_BLOCK decisions are never suppressed by that setting. Use `log_level: debug` for more detail. This is not a per-connection or per-process audit trail. The local logrotate file keeps seven rotated files; forward the JSONL or journal to a protected central log service for longer retention and review.

Pinned eBPF links retain the selected mode if the daemon stops or crashes. Changing `mode` and restarting the service updates those links, including `enforce` to `audit`. A reboot clears the links until the service starts again. To intentionally disable enforcement, use a trusted console or SSH session:

```sh
sudo systemctl stop outbound
sudo /usr/local/bin/outbound --detach-policy
```

## License

[GPL-2.0-only](LICENSE).
