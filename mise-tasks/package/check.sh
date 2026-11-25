#!/bin/sh
#MISE description="Check the exported Signd.app, build/signd.pkg and build/Signd.app.zip against the packaging spec: entitlements, layout, icon, Gatekeeper, the Installer distribution's title, architecture and macOS floor, the places and owners of the login hook and the updater daemon in the payload, and the zipped app's ticket"
# The Release workflow runs this on the package it built, after notarization.
set -eu

fail() {
  echo "✘ $1" >&2
  exit 1
}

app=build/export/Signd.app

[ -x "$app/Contents/MacOS/signd" ] || fail "the bundle has no Contents/MacOS/signd"
[ -f "$app/Contents/Library/LaunchAgents/com.victor-software-house.signd.plist" ] || fail "the bundle has no agent plist in Contents/Library/LaunchAgents"
codesign --verify --strict --deep --verbose=2 "$app" || fail "the bundle's signature does not verify"

# The icon: actool compiled AppIcon into Assets.car, and Xcode merged its name into the Info.plist.
[ "$(plutil -extract CFBundleIconName raw -o - "$app/Contents/Info.plist")" = AppIcon ] || fail "the Info.plist's CFBundleIconName is not AppIcon"
xcrun assetutil --info "$app/Contents/Resources/Assets.car" | grep -q '"Name" *: *"AppIcon"' || fail "Contents/Resources/Assets.car has no AppIcon"

# The entitlements of the signature. PlistBuddy steps through a key path at each colon, so a name keeps its dots.
codesign -d --entitlements :- "$app" > build/entitlements.plist 2> /dev/null
entitlement() { /usr/libexec/PlistBuddy -c "Print :$1" build/entitlements.plist 2> /dev/null; }
case "$(entitlement keychain-access-groups:0)" in
  ?*.com.victor-software-house.signd) ;;
  *) fail "the keychain access group is not <team>.com.victor-software-house.signd" ;;
esac
[ "$(entitlement com.apple.developer.icloud-container-identifiers:0)" = "${CLOUDKIT_CONTAINER:?}" ] || fail "the iCloud container is not $CLOUDKIT_CONTAINER"
! entitlement com.apple.developer.icloud-container-identifiers:1 > /dev/null || fail "the bundle lists more than one iCloud container"
[ "$(entitlement com.apple.developer.icloud-services:0)" = CloudKit ] || fail "the iCloud services are not CloudKit"
[ "$(entitlement com.apple.developer.icloud-container-environment)" = Production ] || fail "the container environment is not Production"
[ "$(entitlement com.apple.developer.aps-environment)" = production ] || fail "the push environment is not production"
echo "✔ the bundle has the agent plist, the AppIcon, and the keychain group, the container $CLOUDKIT_CONTAINER, CloudKit, Production and the push environment in its signature"

spctl --assess --type execute -vv "$app" || fail "Gatekeeper rejects the bundle"
spctl --assess --type install -vv build/signd.pkg || fail "Gatekeeper rejects the package"
echo "✔ Gatekeeper accepts the bundle and the package"

rm -rf build/expanded
pkgutil --expand build/signd.pkg build/expanded
distribution() {
  xmllint --xpath "$1" build/expanded/Distribution
}

# Package.swift's .macOS(.v27) is macOS 27.0.
floor=$(sed -n 's/.*\.macOS(\.v\([0-9]*\)).*/\1.0/p' Package.swift)
[ -n "$floor" ] || fail "Package.swift names no macOS deployment target"

[ "$(distribution 'string(//title)')" = signd ] || fail "the distribution's title is not signd"
[ "$(distribution 'string(//options/@hostArchitectures)')" = arm64 ] || fail "the distribution's hostArchitectures is not arm64"
[ "$(distribution 'string(//allowed-os-versions/os-version/@min)')" = "$floor" ] || fail "the distribution's allowed-os-versions is not macOS $floor"
[ "$(distribution 'string(//domains/@enable_localSystem)')" = true ] || fail "the distribution's domains do not enable the local system"
echo "✔ the package's distribution has the title signd, arm64 as its host architecture, macOS $floor as its floor, and installs on the boot volume"

# The payload lists the login hook and the updater daemon.
# Root owns each with mode 0644, since launchd does not load a job that another user can write.
payload_owner() {
  pkgutil --payload-files build/signd.pkg | grep -Fx "$1" > /dev/null || fail "the package's payload does not list $1"
  owner=$(lsbom -f -p fUGm build/expanded/signd-component.pkg/Bom | awk -F'\t' -v path="$1" '$1 == path { print $2 ":" $3 " " $4 }')
  [ "$owner" = "root:wheel 100644" ] || fail "$1 is owned by and has the mode ${owner:-none}, not root:wheel 100644"
}
payload_owner ./Library/LaunchAgents/com.victor-software-house.signd.login.plist
payload_owner ./Library/LaunchDaemons/com.victor-software-house.signd.updater.plist
echo "✔ the package installs the login hook and the updater daemon, each owned by root:wheel with mode 0644"

# The updater downloads this zip, so its app must carry its own ticket and pass Gatekeeper once unpacked.
rm -rf build/unzipped
ditto -x -k build/Signd.app.zip build/unzipped
xcrun stapler validate build/unzipped/Signd.app || fail "the zipped app has no valid ticket"
spctl --assess --type execute -vv build/unzipped/Signd.app || fail "Gatekeeper rejects the zipped app"
echo "✔ the zipped app has a valid ticket and Gatekeeper accepts it"
