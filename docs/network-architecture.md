# Malware analysis network architecture

## Current qualified baseline: isolated/simulated

Every new analysis defaults to `isolated_simulated`. The malware guest has no
route to the workstation LAN, the Internet, the database, Docker control socket,
UMAT API, CAPE management API, MobSF management interface, or another analysis
guest. The platform analyzer produces its native evidence and UMAT proceeds
directly to platform adaptation, aggregation, and reporting by default. An
operator may independently enable offline C2 analysis of the captured traffic;
that choice does not add a guest route or authorize real destination traffic.

Windows uses the non-forwarding `winstdt-isolated` libvirt network
(`10.66.0.0/24`). Guest-to-host access is limited to DHCP, DNS, and CAPE's result
server on TCP 2042. CAPE receives `route=none` and the
`network_mode=simulated_inetsim` task option.

Android ReDroid uses the Docker `--internal` network `umat-android-isolated`
(`172.30.0.0/24`) on the stable `br-umat-android` bridge. The host initiates ADB
through a host-side relay bound to the Docker gateway; Android cannot initiate connections to the
host or external networks. MobSF's proxy is exposed to the guest through ADB
reverse, not a routable control-plane interface.

The `umat-guest-guard` nftables table provides a second containment boundary:
it denies forwarded traffic from both malware bridges and denies guest-originated
host traffic except the explicitly required Windows DHCP/DNS/result-server
ports. PostgreSQL, UMAT, MobSF and the CAPE management gateway remain bound to
loopback.

ReDroid requires a privileged container and therefore shares the host kernel. The
network controls materially reduce reachability, but they are not a security boundary
against a guest that can exploit the container runtime or kernel. Real handling of
unknown malware should place ReDroid and its Docker daemon on a disposable dedicated
worker host or inside a hardware-virtualized worker VM. That worker receives only a
run-scoped sample and returns evidence over a host-initiated, authenticated channel;
it must have no control-plane or database route. Windows already has a hardware VM
boundary, but the same separated-worker topology remains the production target.

```text
                    management/control plane (loopback only)
       PostgreSQL ─ UMAT API ─ schedulers ─ CAPE/MobSF management
                                ▲                   ▲
                                │ signed artifacts  │ host-initiated control
                    ┌───────────┴───────────┐
                    │ nftables guest guard  │
                    └───────┬─────────┬─────┘
                            │         │
                 virbr-winstdt     br-umat-android
                 no forwarding     Docker --internal
                            │         │
                       Windows     ReDroid
                       malware     malware
```

The intended simulator tier should provide INetSim-compatible DNS, HTTP, HTTPS,
SMTP and common sink services on a dedicated non-management namespace. It must
return synthetic responses, record complete request metadata and PCAP, never
forward requests externally, and be reset after each run. Until that tier is
deployed, “simulated” means fail-closed isolation plus analyzer-local proxy and
instrumentation responses.

## Desired real-world connection architecture

`real_world_egress` is an explicit operator opt-in and is not the current malware
baseline. A production deployment should place it behind a separate sacrificial
egress tier—not behind the workstation's ordinary default route:

```text
malware guest VLAN/namespace
        │
        ▼
stateful deny-by-default firewall
        │  block host, RFC1918, link-local, metadata, multicast and control plane
        ▼
DNS sinkhole + transparent recording proxy
        │
        ▼
rate/volume/time-limited NAT egress gateway
        │
        ▼
dedicated analysis ISP/VPN address, never the corporate LAN
```

Required production controls:

- physically or virtually separate management, evidence, simulator, and egress
  segments with no guest route to management;
- deny IPv4 and IPv6 private/link-local ranges, cloud metadata addresses,
  multicast, inbound connections, lateral guest traffic, and access to the
  Docker/libvirt hosts;
- force DNS through the recording resolver and web traffic through a policy
  proxy where technically possible;
- per-run egress leases with destination, protocol, bandwidth, connection-count,
  byte and wall-clock limits plus an immediate kill switch;
- dedicated disposable public egress, legal authorization and abuse-contact
  handling; never use a production/corporate source address;
- full PCAP, DNS, proxy, firewall and NAT logs correlated to the immutable run ID;
- one-way evidence transfer or tightly authenticated host-initiated collection;
- automatic guest destruction, credential rotation, residue checks and periodic
  escape/containment tests.

The C2 workflow can interpret attempted or simulated traffic in isolated mode,
or completed destination traffic in connection-enabled mode. Enabling real
egress in the UI records intent; it does not by itself certify that a deployment
has the production egress tier.

Platform adaptation is independent of both network mode and C2 policy. CAPE/MobSF findings are
always normalized into the UMAT report. When C2 is disabled, aggregation consumes platform
adaptation directly and records that C2 was skipped. When offline C2 is enabled in isolated mode,
it interprets captured attempted/simulated traffic without creating guest egress. In an authorized
connection-enabled run it may additionally interpret completed destination traffic. In every
mode, platform findings remain available and absence or failure of C2 must not discard them.
