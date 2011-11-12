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

echo "Building iOS library..."
xcodebuild -project simplepgp.xcodeproj -alltargets > /dev/null
echo "Building iOS simulator library..."
SIMSDK=`xcodebuild -showsdks |grep iphonesim |tail -1 |sed 's/.*-sdk \(.*\)/\1/'`
xcodebuild -project simplepgp.xcodeproj -alltargets -sdk ${SIMSDK} >/dev/null
echo "Done!"

