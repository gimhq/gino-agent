#!/bin/sh
mount -t virtiofs work /mnt || exit 1
echo root >/mnt/by-guest-root
setpriv --reuid=1000 --regid=1000 --clear-groups sh -c 'echo u >/mnt/by-guest-uid1000'
setpriv --reuid=2000 --regid=2000 --clear-groups sh -c 'mkdir /mnt/by-guest-uid2000' 2>&1
echo GUEST-VIEW
ls -lnd /mnt /mnt/*
