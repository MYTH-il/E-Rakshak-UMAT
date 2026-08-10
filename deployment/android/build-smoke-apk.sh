#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || "$1" != /* || "$1" == "/" ]]; then
  echo "usage: $0 /absolute/path/to/umat-smoke.apk" >&2
  exit 2
fi
readonly OUTPUT="$1"
readonly SDK_ROOT="${ANDROID_SDK_ROOT:-/usr/lib/android-sdk}"
readonly ANDROID_JAR="$SDK_ROOT/platforms/android-30/android.jar"
readonly BUILD_TOOLS="$SDK_ROOT/build-tools/34.0.0"
readonly WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

mkdir -p "$WORK/src/org/umat/smoke" "$WORK/classes" "$WORK/dex"
cat >"$WORK/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.umat.smoke">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="30" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:theme="@android:style/Theme.Material.Light" android:label="UMAT Smoke"
    android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:name=".ExportedActivity" android:exported="true" />
  </application>
</manifest>
EOF
cat >"$WORK/src/org/umat/smoke/MainActivity.java" <<'EOF'
package org.umat.smoke;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import java.net.HttpURLConnection;
import java.net.URL;
public final class MainActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    TextView message = new TextView(this);
    message.setText("UMAT Android integration smoke test");
    setContentView(message);
    new Thread(() -> {
      try {
        HttpURLConnection request = (HttpURLConnection)
          new URL("http://172.30.0.1:18080/simulated-egress-demo").openConnection();
        request.setConnectTimeout(3000);
        request.getResponseCode();
      } catch (Exception ignored) { }
    }).start();
  }
}
EOF
cat >"$WORK/src/org/umat/smoke/ExportedActivity.java" <<'EOF'
package org.umat.smoke;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
public final class ExportedActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    TextView message = new TextView(this);
    message.setText("UMAT exported activity evidence");
    setContentView(message);
  }
}
EOF

javac --release 8 -classpath "$ANDROID_JAR" -d "$WORK/classes" \
  "$WORK/src/org/umat/smoke/MainActivity.java" "$WORK/src/org/umat/smoke/ExportedActivity.java"
"$BUILD_TOOLS/d8" --lib "$ANDROID_JAR" --output "$WORK/dex" \
  "$WORK/classes/org/umat/smoke/MainActivity.class" \
  "$WORK/classes/org/umat/smoke/ExportedActivity.class"
"$BUILD_TOOLS/aapt" package -f -M "$WORK/AndroidManifest.xml" -I "$ANDROID_JAR" \
  -F "$WORK/unsigned.apk"
(cd "$WORK/dex" && zip -q "$WORK/unsigned.apk" classes.dex)
keytool -genkeypair -noprompt -keystore "$WORK/smoke.jks" -storepass changeit \
  -keypass changeit -alias smoke -keyalg RSA -keysize 2048 -validity 2 \
  -dname "CN=UMAT Smoke,OU=Test,O=UMAT,L=Local,ST=Local,C=XX"
mkdir -p "$(dirname "$OUTPUT")"
"$BUILD_TOOLS/zipalign" -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$WORK/smoke.jks" --ks-pass pass:changeit \
  --key-pass pass:changeit --out "$OUTPUT" "$WORK/aligned.apk"
"$BUILD_TOOLS/apksigner" verify "$OUTPUT"
sha256sum "$OUTPUT"
