# Replicating the sacrificial AWS egress gateway

This guide describes the external half of UMAT's controlled `real_world_egress` topology. It is
for an authorized malware-analysis deployment, not ordinary application traffic. The safe default
remains `isolated_simulated`; a missing tunnel, stale WireGuard handshake, missing policy route,
stopped capture process, or failed firewall check must leave real egress unavailable.

The repository installs and verifies the workstation-side broker and firewall. It does not create
an AWS account, VPC, EC2 instance, Elastic IP address, DNS resolver, WireGuard private keys, abuse
process, or log-retention policy. Those resources belong to the operator and must not be committed
to this repository.

## Exact topology contract

The current implementation expects these names and addresses:

| Item | Required value |
|---|---|
| Workstation WireGuard interface | `wg-umat-egress` |
| Workstation tunnel address | `10.77.0.2/32` |
| Gateway tunnel and recording-DNS address | `10.77.0.53` |
| WireGuard UDP port | `51820` |
| Workstation policy-routing table | `51820` |
| Windows guest network | `10.66.0.0/24` on `virbr-winstdt` |
| Android egress network | `172.31.0.0/24` on `br-umat-egress` |
| Allowed guest application traffic | TCP 80/443 only |
| Guest DNS | Forced to `10.77.0.53`, UDP/TCP 53 |
| Lease lifetime | 90 seconds, refreshed by executor heartbeat |
| Per-run byte ceiling | 100 MiB by default |

UMAT masquerades an authorized guest to `10.77.0.2` before the packet enters WireGuard. The AWS
gateway therefore sees the tunnel peer—not the original guest address. Run and platform identity
remain authoritative in the workstation's mandatory per-run PCAP and audit records. AWS VPC Flow
Logs are a secondary network record and do not replace that PCAP.

```text
Windows/ReDroid guest
        |
        | short-lived nftables lease; forced DNS; TCP 80/443 only
        v
UMAT host guest bridge -- mandatory run PCAP -- source NAT to 10.77.0.2
        |
        | policy table 51820
        v
wg-umat-egress 10.77.0.2/32 ===== UDP 51820 ===== AWS EC2 10.77.0.53
                                                        |
                                              recording DNS + firewall
                                                        |
                                              source NAT to Elastic IP
                                                        |
                                                     Internet
```

## Before creating resources

Record the following outside Git in the deployment change ticket or secrets system:

- authorization owner, purpose, permitted sample classes, start/end date and review interval;
- a dedicated AWS account or at minimum a dedicated VPC with no peering, Transit Gateway,
  corporate VPN, PrivateLink endpoint, or route to a management network;
- AWS Region, VPC/subnet IDs, EC2 instance/ENI ID and Elastic IP allocation ID;
- abuse-contact mailbox and a procedure for provider or third-party complaints;
- budget, traffic and log-volume alarms plus evidence-retention and deletion periods;
- WireGuard public keys and key-rotation date (never private keys);
- the operator's fixed public `/32` allowed to send WireGuard UDP traffic;
- an approved current Ubuntu 24.04 LTS AMI ID for the selected Region.

Use a disposable, non-corporate Elastic IP. Do not attach the gateway VPC to production networks.
Do not store AWS access keys, malware samples or UMAT evidence on the gateway.

## 1. Create the isolated AWS network

The console workflow is the least brittle way to reproduce the AWS resources:

1. Create a dedicated VPC, for example `10.90.0.0/24`, with DNS hostnames disabled unless Systems
   Manager in the chosen design needs them.
2. Attach an Internet Gateway.
3. Create one small public subnet, for example `10.90.0.0/28`, with a route table containing only
   the local VPC route and `0.0.0.0/0` to the Internet Gateway. Do not add IPv6.
4. Create a security group with no SSH ingress. Permit inbound UDP 51820 only from the UMAT
   operator's fixed public `/32`.
5. Permit outbound TCP 80/443 and UDP/TCP 53. These cover the bounded malware policy, resolver,
   package maintenance and Systems Manager over HTTPS. Add nothing merely to make a failed test
   pass; document any expansion.
6. Launch a current Ubuntu 24.04 LTS x86_64 instance with an encrypted root volume, IMDSv2
   required, detailed monitoring as required by policy, and no user-data secret.
7. Attach an IAM instance profile containing only the permissions required for Systems Manager
   and the selected logging destination. Use Session Manager instead of opening SSH.
8. Allocate an Elastic IP in the same network border group and associate it with the instance's
   primary ENI.
9. Disable the EC2 source/destination check on that instance/ENI. AWS otherwise rejects packets
   forwarded through a NAT instance.
10. Enable termination protection if it fits the operational model. The gateway is sacrificial,
    but accidental disappearance during a run should still be distinguishable from deliberate
    rotation.

Equivalent CLI actions may be used in automation. Keep identifiers in task-specific variables and
review every resolved target before executing mutations:

```bash
export UMAT_AWS_REGION="us-east-1"
export UMAT_AWS_INSTANCE_ID="i-replace-me"
export UMAT_AWS_ALLOCATION_ID="eipalloc-replace-me"

aws ec2 associate-address \
  --region "$UMAT_AWS_REGION" \
  --instance-id "$UMAT_AWS_INSTANCE_ID" \
  --allocation-id "$UMAT_AWS_ALLOCATION_ID"

aws ec2 modify-instance-attribute \
  --region "$UMAT_AWS_REGION" \
  --instance-id "$UMAT_AWS_INSTANCE_ID" \
  --source-dest-check '{"Value":false}'
```

Elastic IP addresses incur charges, including while idle. Tag every resource with owner, purpose,
expiry and data classification.

## 2. Bootstrap the gateway through Session Manager

Start a Session Manager shell and install only the required host packages:

```bash
sudo apt-get update
sudo apt-get install --yes wireguard nftables unbound tcpdump
sudo install -d -m 0700 /etc/wireguard
sudo install -d -m 0750 -o root -g adm /var/log/umat-egress
```

Generate the gateway WireGuard private key on the gateway with umask `077`. Generate the
workstation key independently on the workstation. Exchange only public keys. Put private keys in
root-readable files or a root-only secrets mechanism; do not place them in shell history, user
data, S3 objects, tickets or this repository.

Configure `/etc/wireguard/wg0.conf` on AWS, replacing only the key placeholder:

```ini
[Interface]
Address = 10.77.0.53/24
ListenPort = 51820
PrivateKey = GATEWAY_PRIVATE_KEY

[Peer]
PublicKey = WORKSTATION_PUBLIC_KEY
AllowedIPs = 10.77.0.2/32
```

Enable forwarding with a dedicated sysctl file:

```text
# /etc/sysctl.d/90-umat-egress.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
```

Apply it with `sudo sysctl --system`. Enable WireGuard only after the host firewall below is loaded.

## 3. Install the gateway firewall

Use the instance's real public-interface name in place of `ens5`. The policy must:

- accept WireGuard UDP 51820 only from the approved operator public `/32`;
- accept DNS on `wg0` only from `10.77.0.2`;
- forward from `wg0` only source `10.77.0.2`, TCP destinations 80/443;
- reject loopback, private, carrier-grade NAT, link-local, metadata, benchmark and multicast
  destinations before the general web allow rule;
- reject IPv6 forwarding and all unsolicited inbound forwarding;
- permit established replies and masquerade only `10.77.0.2` to the public interface;
- log bounded deny events without allowing a sample to exhaust disk space.

A minimal nftables shape is shown below. Adapt the public interface and operator address, validate
with `nft --check`, and have the final rules reviewed under the deployment's security policy:

```nft
table inet umat_aws_egress {
    set denied_v4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
            192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4
        }
    }

    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "ens5" ip saddr OPERATOR_PUBLIC_IP udp dport 51820 accept
        iifname "wg0" ip saddr 10.77.0.2 ip daddr 10.77.0.53 udp dport 53 accept
        iifname "wg0" ip saddr 10.77.0.2 ip daddr 10.77.0.53 tcp dport 53 accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "ens5" oifname "wg0" ip daddr 10.77.0.2 ct state established,related accept
        iifname "wg0" ip saddr 10.77.0.2 ip daddr @denied_v4 drop
        iifname "wg0" oifname "ens5" ip saddr 10.77.0.2 tcp dport { 80, 443 } \
            ct state new,established accept
    }
}

table ip umat_aws_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "ens5" ip saddr 10.77.0.2 masquerade
    }
}
```

Replace `OPERATOR_PUBLIC_IP` with a single IPv4 address, not `0.0.0.0/0`. Persist the reviewed
rules using the distribution's nftables service, then enable `wg-quick@wg0`.

## 4. Configure recording DNS

Bind Unbound only to `10.77.0.53` and localhost. Allow queries only from `10.77.0.2`; refuse all
other clients. Enable timestamped query and reply logging to a root/`adm`-restricted file, set
finite log rotation, and forward or recursively resolve only according to the deployment policy.

At minimum configure Unbound with:

```text
server:
    interface: 10.77.0.53
    access-control: 0.0.0.0/0 refuse
    access-control: 10.77.0.2/32 allow
    log-queries: yes
    log-replies: yes
    hide-identity: yes
    hide-version: yes
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
```

Verify the installed Unbound version's logging directives before restart. DNS logs contain
potential indicators and must receive the same access control and retention treatment as analysis
evidence. The UMAT host also DNATs guest DNS to this address, so a sample cannot select a different
resolver while its lease is active.

Because Unbound binds to the WireGuard-only address, order it after the tunnel and require the
tunnel unit. Without this dependency, a cold boot can start Unbound before `10.77.0.53` exists and
leave recording DNS unavailable even though WireGuard later becomes healthy:

```ini
# /etc/systemd/system/unbound.service.d/umat-wireguard-ordering.conf
[Unit]
Requires=wg-quick@wg0.service
After=wg-quick@wg0.service
```

Apply the drop-in with `sudo systemctl daemon-reload`, restart Unbound, and verify both services are
active. Include a DNS query through `10.77.0.53` in every cold-boot qualification.

## 5. Configure the UMAT workstation peer

Install WireGuard tools and create `/etc/wireguard/wg-umat-egress.conf` with root-only permissions:

```ini
[Interface]
Address = 10.77.0.2/32
PrivateKey = WORKSTATION_PRIVATE_KEY
Table = off
PostUp = ip route replace table 51820 default dev %i
PostDown = ip route del table 51820 default dev %i

[Peer]
PublicKey = GATEWAY_PUBLIC_KEY
Endpoint = GATEWAY_ELASTIC_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`AllowedIPs = 0.0.0.0/0` does not alter the workstation's ordinary default route because
`Table = off` is mandatory. Only guest source rules installed by `umat-egress-broker.service`
select table 51820. Do not configure an IPv6 address or `::/0`.

Enable the interface, reinstall the current UMAT services/firewall, and restart the broker:

```bash
sudo systemctl enable --now wg-quick@wg-umat-egress
deployment/full-stack/install-services.sh \
  --execute \
  --project-root /absolute/path/to/E-Rakshak-UMAT
sudo systemctl restart umat-guest-guard.service umat-egress-broker.service
```

The service installer creates `/etc/umat/egress-broker.env` with a root-only bearer token. Never
copy that token to the browser, a guest, AWS, logs or documentation.

## 6. AWS logging and monitoring

Enable VPC Flow Logs for the gateway ENI with `ALL` traffic and publish to an encrypted CloudWatch
Logs group or S3 bucket in the operator account. Include source/destination address and port,
protocol, action, bytes, packets, interface ID and timestamps in a custom record format. Flow Logs
are aggregated metadata and can be delayed or incomplete; retain workstation PCAP as the primary
run evidence.

Recommended alarms include:

- instance or status-check failure;
- WireGuard service failure and loss of recent handshake;
- unexpected inbound security-group changes;
- bytes/packets exceeding the approved analysis envelope;
- root volume and log volume approaching capacity;
- Elastic IP reassociation, source/destination-check changes and instance-profile changes;
- monthly cost and data-transfer thresholds.

Optionally capture a bounded rotating PCAP on `wg0` and the public ENI for gateway diagnostics.
Keep it on an encrypted volume, restrict access, and rotate by both time and size. Remote captures
are not automatically associated with a UMAT run ID and must not silently replace the broker's
per-run capture.

## 7. Qualification without malware

Complete all checks with benign traffic before enabling a real sample.

On AWS:

```bash
sudo nft --check --file /etc/nftables.conf
sudo nft list ruleset
sudo wg show wg0
sudo ss -lntup
sudo systemctl is-active wg-quick@wg0 nftables unbound
```

Confirm that UDP 51820 is the only public listener allowed by the security group and that SSH is
closed. From the workstation:

```bash
sudo wg show wg-umat-egress
ip route show table 51820 default
ip rule show | grep 'lookup 51820'
dig +time=5 +tries=1 @10.77.0.53 example.com A +short
curl -fsS http://127.0.0.1:8092/health/ready
sudo nft list sets ip umat_guest_guard
uv run umat-deploy status
```

Expected broker readiness checks are `nft`, `tcpdump`, `uplink_present`, `uplink_up`,
`recent_wireguard_handshake`, `policy_route`, `source_policy_rules`, `ipv4_forwarding`,
`windows_policy_set`, and `android_policy_set`, all `true`.

Then perform a benign disposable-guest acceptance run and prove all of the following:

1. no lease means no guest Internet access;
2. an active lease reaches the recording resolver and TCP 80/443 only;
3. RFC1918, metadata, non-web ports, IPv6, host and management destinations remain blocked;
4. the run PCAP exists before the firewall lease is granted and is non-empty afterward;
5. stopping the executor or broker removes access within the 90-second kernel timeout;
6. exceeding the byte ceiling revokes the lease;
7. the resulting UMAT run configuration and audit trail identify the selected network mode;
8. DNS, workstation PCAP and AWS flow records agree on timestamps and destinations.

Do not test containment by weakening it or by using live malware before the benign gates pass.

## Routine operation and key rotation

- Keep `isolated_simulated` as the default and approve real egress case by case.
- Patch and reboot the gateway on a documented maintenance schedule; readiness should fail closed
  during maintenance.
- Rotate both WireGuard key pairs and the Elastic IP on the deployment's risk schedule or after any
  suspected exposure. Change one peer at a time and repeat benign qualification.
- Review security-group, route-table, source/destination-check, IAM and flow-log configuration for
  drift. AWS Config can automate part of this review.
- Inspect abuse notifications and unexpected destination/volume patterns after every authorized
  campaign.
- Retain only the evidence required by policy; securely delete expired DNS/PCAP logs and old
  snapshots.

## Emergency stop and teardown

To stop egress immediately, stop the workstation broker first. Its shutdown revokes active leases:

```bash
sudo systemctl stop umat-egress-broker.service
sudo nft flush set ip umat_guest_guard windows_egress_v4
sudo nft flush set ip umat_guest_guard android_egress_v4
sudo systemctl stop wg-quick@wg-umat-egress
```

Then stop the EC2 instance or remove UDP 51820 ingress. Before destroying AWS resources, export only
the logs required by policy, rotate/revoke keys, disassociate and release the Elastic IP, terminate
the instance, delete its volumes/snapshots, remove Flow Logs and their IAM role, then remove the
security group, subnet route table, subnet, Internet Gateway and VPC in dependency order.

After teardown, `curl http://127.0.0.1:8092/health/ready` must report `not_ready`, and direct API or
UI requests for `real_world_egress` must remain unavailable. Preserve the authorization, change,
qualification and deletion records—not the gateway's private keys.

## Known boundary

The current broker enforces topology readiness, short-lived leases, mandatory local capture and
network limits. The separate product requirement for explicit per-run administrator identity,
reason and immutable policy-snapshot authorization is not implemented merely by provisioning this
gateway. Until that application-level authorization is added and qualified, deployment owners must
not treat a healthy AWS tunnel alone as complete production authorization.

## AWS references

Verify commands and service behavior against the current AWS documentation before every build:

- [Connect through AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
- [Allocate and manage Elastic IP addresses](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-eips.html)
- [NAT instance design and limitations](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html)
- [Create a NAT instance and disable source/destination checks](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-nat-instances.html)
- [VPC Flow Logs fundamentals](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-basics.html)
- [VPC Flow Log record fields](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
