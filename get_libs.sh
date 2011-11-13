#!/bin/sh

IOS_LIB_URL="http://ios-static-libraries.googlecode.com/files/ios-libraries-2011-03-10-065803.zip"
IOS_LIB_FILE="ios-libraries-2011-03-10-065803.zip"

if [ ! -d "Binaries" ]; then
    if [ ! -e ${IOS_LIB_FILE} ]; then
	wget ${IOS_LIB_URL} > /dev/null
    fi
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
exit 0