# Android execution host

Phase 5 uses the pinned Android/MobSF fork through its HTTP API. Upstream source is
checked out outside this repository and verified before its image is built.
The committed patch series fixes the pinned Docker build ordering, makes dependency installation
fail closed, pins Poetry/base-image inputs, consumes the upstream `poetry.lock`, and packages the
checksum-verified Frida 17.17.0 x86_64 server in the image. Runtime analysis never downloads a
Frida binary. MobSF refuses to begin instrumentation unless the packaged server matches the Python
client, starts in ReDroid, and answers a bounded readiness probe. The complete patch-series digest
and resulting image digest are recorded in the dependency lock and deployment manifest.

The default worker is the digest-pinned amd64 ReDroid Android 11/API 30 image, executed inside the
disposable KVM worker provisioned under `deployment/android-worker/`. The host-side Android
executor is disabled after cutover. Live screen/input, Frida, activity testing, TLS/proxy controls
and evidence uploads continue through the existing signed UMAT command protocol.
It uses BinderFS, a disposable writable `/data`, a writable container-backed
`/system`, root operations through `su 0`, and container-local packet capture.
The API-30 AOSP x86_64 emulator remains an optional higher-fidelity fallback.

UMAT imports MobSF's native security mappings from the signed static report. Code findings retain
OWASP MASVS/MSTG, OWASP Mobile and CWE references, while MobSF behavior labels are retained as the
Android TTP-equivalent taxonomy. These are displayed as security mappings with source provenance;
UMAT does not fabricate Mobile ATT&CK identifiers that MobSF did not assert.

During dynamic analysis the executor polls MobSF's API monitor and records the first UTC
observation of each immutable row. Sensitive Android API calls are normalized into the versioned
`contracts/android/android-access-events.schema.json` contract with process identity, API,
operation, object reference, source hash, and bounded timestamp uncertainty. Eligible events may
be associated with nearby PCAP observations, but the result is always weak confidence and carries
`android_temporal_correlation_only`; timing does not prove payload contents or data theft.

Host prerequisites are Docker, BinderFS, Java, Android platform tools,
command-line tools, the Android emulator, `socat`, KVM access, and
`system-images;android-30;default;x86_64` for the fallback profile.
The required ReDroid tooling uses Android platform tools under `/usr/lib/android-sdk`. The optional
AVD fallback is pinned separately to emulator 34.1.19 under `/opt/android-sdk-34`; a newer distro
emulator may coexist but does not replace that fallback identity.

Build the pinned MobSF image:

```bash
deployment/android/bootstrap.sh /opt/umat/upstreams/android-erakshak
```

Set a random database password and the immutable digest for the approved
`postgres:16` image, then start MobSF on `127.0.0.1:8001`:

```bash
export MOBSF_DATABASE_PASSWORD='replace-with-random-secret'
export MOBSF_POSTGRES_IMAGE_DIGEST='approved-linux-amd64-manifest-digest'
docker compose -f deployment/android/compose.yaml up -d
```

Create a UMAT enrollment token scoped to `platform_analysis`, retrieve the MobSF
API key from the local MobSF instance, and run:

```bash
uv run umat-android-executor run \
  --mobsf-url http://127.0.0.1:8001 \
  --mobsf-api-key "$MOBSF_API_KEY" \
  --avdmanager /usr/bin/avdmanager \
  --emulator /opt/android-sdk-34/emulator/emulator \
  --adb /usr/bin/adb \
  --adb-relay /usr/bin/socat \
  --adb-relay-bind-address 172.17.0.1 \
  --enrollment-token "$UMAT_ANDROID_ENROLLMENT_TOKEN"
```

The relay is created only while a disposable AVD is running and binds the Docker
bridge address, not every host interface. If Docker uses a bridge other than
`docker0`, supply that bridge's host IPv4 address. MobSF resolves
`emulator-5554` to `host.docker.internal:5555` inside its container.

Interactive runs are brokered through UMAT. The platform-analysis executor retains the disposable
ReDroid worker only while an `android_dynamic_sessions` record is ready, polls allowlisted commands
over its signed lease, and finalizes automatically on cancellation, stage timeout or session expiry.
The default MobSF compose container name is `android-mobsf-1`; deployments using a different
project name must set `UMAT_ANDROID_MOBSF_CONTAINER` so Java and Smali exports can be registered as
UMAT evidence artifacts.

The executor receives no PostgreSQL credentials. The default profile creates a
run-specific privileged ReDroid container constrained to 4 vCPU/4096 MiB,
validates the x86_64 guest ABI, proves `/system` writability, captures PCAP in
the container network namespace, performs bounded ADB stimulation, registers a
signed bundle, and destroys the container and data tree. MobSF and Android
workers must be isolated from production/user networks before hostile samples
are executed.

After KVM-worker cutover, the installer disables the legacy host Android executor to prevent a
claim race. The worker uses `management0` (`10.67.0.10`) for signed UMAT and egress-broker relay
traffic and presents the post-NAT malware boundary as `10.68.0.10` on `br-umat-malware`. The host
firewall remains closed without a captured lease. Real-egress qualification additionally permits
only the exact SpyMax tuple `37.120.141.140:7775/TCP`; it does not create a general port-7775 rule.

ReDroid is qualified by full SpyMax acceptance run
`01a00541-5f6a-7c54-aa05-fb1a7b41bb64`. It completed pinned Frida readiness and injection with no
API-monitor polling errors, persisted normalized access events, captured guest and gateway PCAPs,
and completed C2 processing, both adaptation stages, aggregation, and final report generation.
ARM images are not provisioned.

For a harmless runtime acceptance input, generate the repository-owned smoke
application outside the source tree:

```bash
deployment/android/build-smoke-apk.sh "$PWD/var/android-smoke/umat-smoke.apk"
```
