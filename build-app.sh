#!/bin/bash
# Builds only in dist; never installs, activates extensions, edits proxies, or starts a tunnel.
set -euo pipefail
cd "$(dirname "$0")"
scratch="${CONNECTION_GUARD_BUILD_DIR:-/tmp/ai-connection-guard-build}"
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/ai-guard-clang-cache}"
swift build --disable-sandbox --scratch-path "$scratch" -c release
bin_dir=$(swift build --disable-sandbox --scratch-path "$scratch" -c release --show-bin-path)
bundle="$PWD/dist/AI Connection Guard.app"
filter="$PWD/dist/Prepared Extension/ConnectionGuard.Filter.systemextension"
mkdir -p "$bundle/Contents/MacOS" "$filter/Contents/MacOS"
cp "$bin_dir/ConnectionGuard" "$bundle/Contents/MacOS/ConnectionGuard"
cp "$bin_dir/ConnectionGuardFilter" "$filter/Contents/MacOS/ConnectionGuardFilter"
cp Resources/Filter-Info.plist "$filter/Contents/Info.plist"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ConnectionGuard</string>
<key>CFBundleIdentifier</key><string>com.kostenchuksergey.ConnectionGuard</string>
<key>CFBundleName</key><string>AI Connection Guard</string>
<key>CFBundleDisplayName</key><string>AI Connection Guard</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleDevelopmentRegion</key><string>ru</string>
</dict></plist>
PLIST
# The provider is outside the .app and has no usable provisioning profile.
# Ad-hoc signatures below only make the local build inspectable.
/usr/bin/codesign --force --sign - "$filter"
/usr/bin/codesign --force --sign - "$bundle"
printf 'Prepared app: %s\n' "$bundle"
