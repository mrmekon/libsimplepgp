#!/bin/sh

echo "Building iOS library..."
xcodebuild -project simplepgp.xcodeproj -alltargets > /dev/null
echo "Building iOS simulator library..."
SIMSDK=`xcodebuild -showsdks |grep iphonesim |tail -1 |sed 's/.*-sdk \(.*\)/\1/'`
xcodebuild -project simplepgp.xcodeproj -alltargets -sdk ${SIMSDK} >/dev/null
echo "Done!"

