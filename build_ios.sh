#!/bin/sh

IOS_LIB_URL="http://ios-static-libraries.googlecode.com/files/ios-libraries-2011-03-10-065803.zip"
IOS_LIB_FILE="ios-libraries-2011-03-10-065803.zip"

if [ ! -d "Binaries" ]; then
    wget ${IOS_LIB_URL} > /dev/null
    if [ ! -e ${IOS_LIB_FILE} ]; then
	echo "FAILED TO DOWNLOAD IOS LIBRARIES.  CANNOT CONTINUE."
	exit 1
    fi
    unzip ${IOS_LIB_FILE} > /dev/null
    if [ $? -ne 0 ]; then
	echo "Unzip failed.  CANNOT CONTINUE."
	exit 1
    fi
fi


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

