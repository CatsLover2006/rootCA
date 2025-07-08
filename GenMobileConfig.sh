#!/bin/sh

#  GenMobileConfig.sh
#
#
#  Created by Half-Qilin on 2025-08-08.
#

namespace=$(uuid -v 4)

rm beeg.unsigned.plist
echo """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <array>""" > beeg.unsigned.plist

get_cert_name () {
    name=$3
    case $name in
        "Apple Root CA") # Goof by me
            name="Apple Inc. Root"
            ;;
        "GlobalSign") # Globalsign didn't give proper names...
            name="GlobalSign Root $(openssl x509 -noout -subject -in $1 -nameopt multiline | grep organizationalUnitName | sed -n 's/.*- //p')"
            ;;
        "Apple Worldwide Developer Relations Certification Authority") # Apple did it too
            name="Apple WWDR CA $(openssl x509 -noout -subject -in $1 -nameopt multiline | grep organizationalUnitName | sed -n 's/.*= //p')"
            ;;
        *) # Most are fixed by this
            name=${name//-/}
            name=${name//Certification/Certificate}
            name=${name//Certificate Authority/CA}
            name=${name//Worldwide Developer Relations/WWDR}
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
                <string>ca.litten.root.$(echo "$1" | md5sum)</string>
                <key>PayloadType</key>
                <string>com.apple.security.pkcs1</string>
                <key>PayloadUUID</key>
                <string>$(uuid)</string>
                <key>PayloadVersion</key>
                <integer>1</integer>
            </dict>""" >> beeg.unsigned.plist
        echo $(file $1)
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
        scan_dir $(basename $i)
    fi
done

echo """        </array>
        <key>PayloadDisplayName</key>
        <string>Hanabi's Updated Root CA's</string>
        <key>PayloadDescription</key>
        <string>All the up-to-date SSL certificates from https://tlsroot.litten.ca! Last updated $(date -u +"%Y-%m-%d %H:%M:%S UTC").</string>
        <key>PayloadIdentifier</key>
        <string>ca.litten.rootca</string>
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
</plist>""" >> beeg.unsigned.plist

if [ -f beeg.mobileconfig ]; then
    rm beeg.mobileconfig
fi

valid="$(/usr/bin/security find-identity -p codesigning -v | grep "valid identities found")"
valid="${valid// /}"

if [[ "$valid" == "0valididentitiesfound" ]]; then
    cp beeg.unsigned.plist beeg.mobileconfig
    echo "Unable to sign mobileconfig file, will leave unsigned."
else
    certnum=1
    if [[ "$valid" != "1valididentitiesfound" ]]; then
        echo "Pick a signing certificate from the following:"
        echo "$(/usr/bin/security find-identity -p codesigning -v | grep -v "valid identities found")"
        read certnum
    fi
    echo "Using certificate number $certnum to sign mobileconfig file."
    if [[ "$(/usr/bin/security find-identity -p codesigning -v | grep -v "valid identities found" | grep "$certnum)" )" =~ \"(.*)\" ]]; then
        idname=${BASH_REMATCH[1]}
        /usr/bin/security cms -S -N "$idname" -i beeg.unsigned.plist -o beeg.mobileconfig
    else
        cp beeg.unsigned.plist beeg.mobileconfig
        echo "Error in signing mobileconfig file, will leave unsigned."
    fi
fi
