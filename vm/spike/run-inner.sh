#!/usr/bin/env bash
# Runs inside the spike runner container (non-root, /dev/kvm): starts spike-host, boots
# the guest for each criterion and prints `SUMMARY` lines.
#
#   run-inner.sh <out dir> <run dir> <boot runs>
set -uo pipefail

OUT=$1
RUN=$2
RUNS=$3
VMM="$OUT/bin/spike-vmm"
ROOT="$OUT/rootfs"
VCPUS=1
MEM=512
export LD_LIBRARY_PATH="$OUT/lib"

summary() { echo "SUMMARY $*"; }

# boot <name> <vmm args...>: runs the VMM with per-line timestamps (µs since launch) in
# $RUN/<name>.log and the VmRSS/VmHWM samples (kB, every 50 ms) in $RUN/<name>.rss.
boot() {
  local name=$1 t0 pid status
  shift
  t0=${EPOCHREALTIME/./}
  "$VMM" --vcpus "$VCPUS" --mem "$MEM" --root "$ROOT" "$@" </dev/null \
    > >(while IFS= read -r line; do echo "$(( ${EPOCHREALTIME/./} - t0 )) $line"; done >"$RUN/$name.log") 2>&1 &
  pid=$!
  : >"$RUN/$name.rss"
  while kill -0 "$pid" 2>/dev/null; do
    awk -v t="$(( ${EPOCHREALTIME/./} - t0 ))" '/^VmRSS/{r=$2} /^VmHWM/{h=$2} END{if (r) print t, r, h}' \
      "/proc/$pid/status" >>"$RUN/$name.rss" 2>/dev/null
    sleep 0.05
  done
  wait "$pid"
  status=$?
  sleep 0.2
  echo "== $name (exit $status)"
  cat "$RUN/$name.log"
  return "$status"
}

# first_us <name> <pattern>: launch-relative µs of the first console line matching pattern.
first_us() { awk -v p="$2" '$0 ~ p {print $1; exit}' "$RUN/$1.log"; }

# peak_kb <name>: max of the sampled VmRSS and VmHWM (VmHWM is updated lazily).
peak_kb() { awk '{m = $2 > m ? $2 : m; m = $3 > m ? $3 : m} END{print m}' "$RUN/$1.rss"; }

median() { sort -n | awk '{a[NR]=$1} END{print (NR%2 ? a[(NR+1)/2] : int((a[NR/2]+a[NR/2+1])/2))}'; }

echo "== runner: uid=$(id -u) gid=$(id -g) groups=$(id -G) kernel=$(uname -r)"
"$OUT/bin/spike-host" "$RUN/vsock.sock" "$RUN/net.sock" 127.0.0.1:18080 >"$RUN/host.log" 2>&1 &
host=$!
for _ in $(seq 1 50); do grep -q ready "$RUN/host.log" 2>/dev/null && break; sleep 0.1; done

# a. virtiofs root + console, boot latency, RSS.
times=()
for i in $(seq 1 "$RUNS"); do
  boot "boot$i" -- /bin/sh /usr/local/lib/spike/boot.sh
  us=$(first_us "boot$i" BOOT-OK)
  times+=("${us:-NA}")
done
kernel=$(awk '/BOOT-OK/{print $3; exit}' "$RUN/boot1.log")
rootfs=$(awk '/BOOT-OK/{print $5; exit}' "$RUN/boot1.log")
ok=$(grep -l BOOT-OK "$RUN"/boot*.log | wc -l)
summary "a boot+console: $([[ $ok -eq $RUNS ]] && echo PASS || echo FAIL) ($ok/$RUNS runs printed BOOT-OK; guest kernel $kernel; $rootfs)"
summary "metric boot-to-output-ms: median=$(printf '%s\n' "${times[@]}" | median | awk '{printf "%.1f", $1/1000}') runs=[$(printf '%s\n' "${times[@]}" | awk '{printf "%s%.1f", (NR>1 ? ", " : ""), $1/1000}')] vcpus=$VCPUS mem=${MEM}MiB"
peaks=$(for i in $(seq 1 "$RUNS"); do peak_kb "boot$i"; done | median)
summary "metric vmm-peak-rss-short-run-kB: median=$peaks ($RUNS boot runs) vcpus=$VCPUS mem=${MEM}MiB"

for cfg in 1:512 2:2048; do
  VCPUS=${cfg%:*} MEM=${cfg#*:}
  boot "rss-$VCPUS-$MEM" -- /bin/sh /usr/local/lib/spike/rss.sh
  ready=$(first_us "rss-$VCPUS-$MEM" READY)
  steady=$(awk -v r="$ready" '$1 > r + 3000000 {print $2; exit}' "$RUN/rss-$VCPUS-$MEM.rss")
  summary "metric vmm-rss-kB: steady=$steady (VmRSS 3 s after READY, guest idle) peak=$(peak_kb "rss-$VCPUS-$MEM") vcpus=$VCPUS mem=${MEM}MiB"
done
VCPUS=1 MEM=512

# b. vsock to a host Unix socket, TSI disabled.
boot vsock --vsock 5000="$RUN/vsock.sock" -- /bin/sh /usr/local/lib/spike/vsock.sh
rtt=$(grep -o 'VSOCK-RTT.*' "$RUN/vsock.log")
notsi=$(grep -o 'spike-guest: .*' "$RUN/vsock.log" | head -1)
summary "b vsock: $([[ -n $rtt ]] && echo PASS || echo FAIL) ($rtt; TSI off: guest $(grep -o 'IFACES.*' "$RUN/vsock.log"), tcp to 1.1.1.1:80 -> ${notsi:-connected})"

# c. virtiofs rw share, ownership.
mkdir -p "$RUN/share"
echo host >"$RUN/share/by-host"
boot share --share work="$RUN/share" -- /bin/sh /usr/local/lib/spike/share.sh
host_view=$(cd "$RUN/share" && stat -c '%n=%u:%g' -- * | tr '\n' ' ')
pass=FAIL
[[ -f $RUN/share/by-guest-root && -f $RUN/share/by-guest-uid1000 ]] && pass=PASS
summary "c virtiofs-rw: $pass (host view: $host_view; vmm uid $(id -u))"

# d. virtio-net unixstream -> nsplane-ether -> nsplane-netstack -> loopback backend.
boot net --net "$RUN/net.sock" -- /bin/sh /usr/local/lib/spike/net.sh
sleep 0.5
echo "== spike-host"
cat "$RUN/host.log"
tcp=$(grep -o 'TCP-REPLY.*' "$RUN/net.log")
stats=$(grep -o 'ether: guest disconnected.*' "$RUN/host.log" | tail -1)
pass=FAIL
[[ $tcp == *'echo hello-from-guest'* ]] && grep -q 'ADDR 10.0.2.15' "$RUN/net.log" && pass=PASS
summary "d net: $pass ($(grep -o 'ADDR.*' "$RUN/net.log"); $(grep -o 'ARP.*' "$RUN/net.log"); $(grep -o 'ROUTE.*' "$RUN/net.log"); ${tcp:-no TCP reply})"
summary "d dns: $(grep -o 'RESOLV .*' "$RUN/net.log"); $(grep -o 'RESOLV-WRITE.*' "$RUN/net.log")"
summary "d ether-stats: ${stats#ether: guest disconnected, }"
net_us=$(first_us net 'ADDR')
summary "metric boot-to-output-with-dhcp-ms: $(awk -v u="${net_us:-0}" 'BEGIN{printf "%.1f", u/1000}')"

kill "$host" 2>/dev/null
wait "$host" 2>/dev/null
exit 0
