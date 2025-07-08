#!/bin/sh

#  GenMobileConfig.sh
#
#
#  Created by Half-Qilin on 2025-08-08.
#

namespace="a19f30d6-0bff-469a-8c57-9311bce6edec"

echo """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <array>"""

get_cert_name () {
    name=$3
    case $name in
        "Apple Root CA") # Goof by me
            name="Apple Inc. Root"
            ;;
        "GlobalSign") # Globalsign didn't give proper names...
            name="GlobalSign Root $(openssl x509 -noout -subject -in $1 -nameopt multiline | grep organizationalUnitName | sed -n 's/.*- //p')"
            ;;
        *) # Most are fixed by this
            name=${name//-/}
            name=${name//Certification/Certificate}
            name=${name//Certificate Authority/CA}
            name=${name//  / }
            ;;
    esac
    eval "$2=\"$name\""
}

scan_cert () {
    if [ -f $1 ]; then
        certname=$(openssl x509 -noout -subject -in $1 -nameopt multiline | grep commonName | sed -n 's/ *commonName *= //p')
        get_cert_name $1 certname "$certname"
        uuid=$(uuid -v 5 $2 "$certname")
        echo """            <dict>
                <key>PayloadCertificateFileName</key>
                <string>$(basename $1)</string>
                <key>PayloadContent</key>
                <data>$(base64 -i $1)</data>
                <key>PayloadDisplayName</key>
                <string>$certname</string>
                <key>PayloadIdentifier</key>
                <string>com.apple.security.root.$(uuid)</string>
                <key>PayloadType</key>
                <string>com.apple.security.root</string>
                <key>PayloadUUID</key>
                <string>$(uuid)</string>
                <key>PayloadVersion</key>
                <integer>1</integer>
            </dict>"""
    fi
}

scan_dir () {
    for i in $1/*.crt; do
        scan_cert "$i" $namespace
    done
    for i in $1/*.cer; do
        scan_cert "$i" $namespace
    done
    for i in $1/*.der; do
        scan_cert "$i" $namespace
    done
}

scan_dir .

for i in */; do
    # Can't include out-of-date certs
    if [[ $i != *"old"* ]]; then
        scan_dir $i
    fi
done

echo """        </array>
        <key>PayloadDisplayName</key>
        <string>Hanabi's Updated Root CA's</string>
        <key>PayloadDescription</key>
        <string>All the up-to-date SSL certificates from https://tlsroot.litten.ca! Last updated $(date -u +"%Y-%m-%d %H:%M:%S UTC").</string>
        <key>PayloadIdentifier</key>
        <string>HanabiRootCA.$namespace</string>
        <key>PayloadScope</key>
        <string>System</string>
        <key>PayloadType</key>
        <string>Configuration</string>
        <key>PayloadUUID</key>
        <string>$namespace</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>TargetDeviceType</key>
        <integer>1</integer>
    </dict>
</plist>"""
