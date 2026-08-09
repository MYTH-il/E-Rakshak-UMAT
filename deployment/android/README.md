# Android execution host

Phase 5 uses the pinned Android/MobSF fork through its HTTP API. Upstream source is
checked out outside this repository and verified before its image is built.
The committed patch fixes the pinned Docker build ordering, makes dependency
installation fail closed, pins Poetry/base-image inputs, and consumes the
upstream `poetry.lock`; the patch digest is recorded in the dependency lock.

Host prerequisites are Docker, Java, Android platform tools, command-line tools,
the Android emulator, `socat`, KVM access, and
`system-images;android-30;google_apis;x86_64`.
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

The executor receives no PostgreSQL credentials. Each claim creates a wiped,
run-specific API-30 AVD, captures PCAP using the emulator, performs bounded ADB
stimulation, registers a signed bundle, and removes the AVD in cleanup. MobSF
and the emulator must be isolated from production/user networks before hostile
samples are executed.

The pinned container and a real signed APK static-analysis round trip are
validated. The dependency lock remains `candidate` until that APK also completes
dynamic analysis. On the current host, both the UMAT lifecycle and the pinned
upstream launcher reproduce an API-30 second-boot offline state after disabling
verity. The executor fails closed to a signed partial/static bundle with explicit
caveats; this does not promote the Android runtime lock. Offline tests do not
constitute runtime validation.

For a harmless runtime acceptance input, generate the repository-owned smoke
application outside the source tree:

```bash
deployment/android/build-smoke-apk.sh "$PWD/var/android-smoke/umat-smoke.apk"
```
