#!/bin/sh
echo "BOOT-OK $(uname -r) uid=$(id -u) root=$(awk '$2=="/"{print $3}' /proc/mounts)"
