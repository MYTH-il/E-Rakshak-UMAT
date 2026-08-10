# Android execution host

Phase 5 uses the pinned Android/MobSF fork through its HTTP API. Upstream source is
checked out outside this repository and verified before its image is built.
The committed patch fixes the pinned Docker build ordering, makes dependency
installation fail closed, pins Poetry/base-image inputs, and consumes the
upstream `poetry.lock`; the patch digest is recorded in the dependency lock.

The default worker is the digest-pinned amd64 ReDroid Android 11/API 30 image.
It uses BinderFS, a disposable writable `/data`, a writable container-backed
`/system`, root operations through `su 0`, and container-local packet capture.
The API-30 AOSP x86_64 emulator remains an optional higher-fidelity fallback.

Host prerequisites are Docker, BinderFS, Java, Android platform tools,
command-line tools, the Android emulator, `socat`, KVM access, and
`system-images;android-30;default;x86_64` for the fallback profile.
This workstation installs the SDK under `/usr/lib/android-sdk`.
Runtime validation used Android emulator 37.1.11; Ubuntu's packaged 34.1.19
must be upgraded with `sdkmanager emulator` before acceptance testing.

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
  --emulator /usr/lib/android-sdk/emulator/emulator \
  --adb /usr/bin/adb \
  --adb-relay /usr/bin/socat \
  --adb-relay-bind-address 172.17.0.1 \
  --enrollment-token "$UMAT_ANDROID_ENROLLMENT_TOKEN"
```

The relay is created only while a disposable AVD is running and binds the Docker
bridge address, not every host interface. If Docker uses a bridge other than
`docker0`, supply that bridge's host IPv4 address. MobSF resolves
`emulator-5554` to `host.docker.internal:5555` inside its container.

The executor receives no PostgreSQL credentials. The default profile creates a
run-specific privileged ReDroid container constrained to 4 vCPU/4096 MiB,
validates the x86_64 guest ABI, proves `/system` writability, captures PCAP in
the container network namespace, performs bounded ADB stimulation, registers a
signed bundle, and destroys the container and data tree. MobSF and Android
workers must be isolated from production/user networks before hostile samples
are executed.

ReDroid is qualified by full acceptance run
`019fe8ab-37c7-7eca-b139-167f2b8052ea`. It completed dynamic analysis, system
CA installation, Frida injection, PCAP capture, C2 processing, both adaptation
stages, aggregation, and report generation. ARM images are not provisioned.

For a harmless runtime acceptance input, generate the repository-owned smoke
application outside the source tree:

```bash
deployment/android/build-smoke-apk.sh "$PWD/var/android-smoke/umat-smoke.apk"
```
