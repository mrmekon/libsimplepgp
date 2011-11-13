#!/bin/sh

sh get_libs.sh
if [ $? -ne 0 ]; then exit 1; fi;

echo "Building iOS library (armv6)..."
xcodebuild ARCHS="armv6" -project simplepgp.xcodeproj -alltargets \
    -configuration "Release armv6" > /dev/null
if [ $? -ne 0 ]; then exit 1; fi;

echo "Building iOS library (armv7)..."
xcodebuild ARCHS="armv7" -project simplepgp.xcodeproj -alltargets \
    -configuration "Release armv7" > /dev/null
if [ $? -ne 0 ]; then exit 1; fi;

echo "Building iOS library (simulator)..."
SIMSDK=`xcodebuild -showsdks |grep iphonesim |tail -1 |sed 's/.*-sdk \(.*\)/\1/'`
xcodebuild ARCHS="i386" -project simplepgp.xcodeproj -alltargets -sdk ${SIMSDK} \
    -configuration "Debug simulator" > /dev/null
if [ $? -ne 0 ]; then exit 1; fi;

echo "Done!"

