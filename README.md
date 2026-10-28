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
for file in "$ASSET" "$ASSET.sha256" config.example.yaml outbound.service outbound.logrotate LICENSE SHA256SUMS; do
  curl -fL --retry 3 -O "${BASE}/${file}" || exit 1
done
sha256sum --check "$ASSET.sha256" || exit 1
sha256sum --ignore-missing --check SHA256SUMS || exit 1
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
  log_reverse_dns: true
  dns_refresh_interval: "30s"
  max_ip_entries: 1024
  cover_all_udp: false
allowlist:
  domains:
    - "metadata.google.internal"
    - "*.ubuntu.com"
    - "*.googleapis.com"
    - "*.amazonaws.com"
  cidrs:
    - "203.0.113.10/32"       # example only: replace with your destination IP
```

Exact domains are resolved at startup and refreshed periodically. Wildcards learn IPs from ordinary UDP DNS replies; `*.amazonaws.com` does not include `amazonaws.com` itself. Add it separately if needed. The final decision uses destination **IP**, so another service or proxy on an allowed IP can also be reached.

All outbound TCP ports, including SSH port 22, follow the same allowlist. UDP port 443 is covered by default. To cover other UDP ports, set `cover_all_udp: true` and allow your DNS resolver IP in `cidrs` first. DNS over HTTPS/TLS/TCP and cached DNS answers cannot teach wildcard IPs to the DNS hook.

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
sudo /usr/local/bin/outbound --policy-status  # enforce mode only
```

In `enforce` mode, pinned eBPF links keep the last policy attached if the daemon stops or crashes. A reboot clears those links until the service starts again. To intentionally disable enforcement, use a trusted console or SSH session:

```sh
sudo systemctl stop outbound
sudo /usr/local/bin/outbound --detach-policy
```

## License

[GPL-2.0-only](LICENSE).
