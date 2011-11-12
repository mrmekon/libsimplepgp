#!/bin/sh

echo "Building iOS library..."
xcodebuild -project simplepgp.xcodeproj -alltargets > /dev/null
echo "Building iOS simulator library..."
xcodebuild -project simplepgp.xcodeproj -alltargets -sdk iphonesimulator4.3 >/dev/null
echo "Done!"

