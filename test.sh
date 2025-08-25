#!/bin/bash

device=$(sudo losetup  |grep test.img | awk '{print $1}'|head -n1)
if [ -z "$device" ]; then
	truncate test.img --size 1GB
	device=$(sudo losetup -f --show test.img)
fi
echo "Device $device"
echo "cLevisTest1234" > key
if [ ! $(sudo cryptsetup isLuks $device) ]; then
	yes "YES"| sudo cryptsetup luksFormat -d key --force-password $device
fi
sudo clevis luks bind -f -k key -d $device trustee "$(cat data.json)"
sudo clevis luks list -d $device
sudo clevis luks unlock -d $device -n myroot
