#!/usr/bin/env bash
# Run as root on a disposable Linux runner with iproute2, iptables and TShark.
set -euo pipefail
client="stun-client-$$"
router="stun-router-$$"
server="stun-server-$$"
namespaces=()
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    for ns in "${namespaces[@]}"; do ip netns del "$ns"; done
}
trap cleanup EXIT
for ns in "$client" "$router" "$server"; do
    ip netns add "$ns"
    namespaces+=("$ns")
    ip -n "$ns" link set lo up
done
ip -n "$client" link add lab0 type veth peer name inside netns "$router"
ip -n "$server" link add lab0 type veth peer name outside netns "$router"
ip -n "$client" addr add 192.0.2.10/24 dev lab0
ip -n "$router" addr add 192.0.2.1/24 dev inside
ip -n "$router" addr add 198.51.100.1/24 dev outside
ip -n "$server" addr add 198.51.100.2/24 dev lab0
ip -n "$router" link set inside up
ip -n "$router" link set outside up
ip -n "$client" link set lab0 up
ip -n "$server" link set lab0 up
ip -n "$client" route add 198.51.100.0/24 via 192.0.2.1
ip -n "$server" route add 192.0.2.0/24 via 198.51.100.1
ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1
python_exe=${1:-python3}
ip netns exec "$server" "$python_exe" -m tests.network.lab serve &
server_pid=$!
ip netns exec "$client" "$python_exe" -m tests.network.lab 192.0.2.10 192.0.2.10
ip netns exec "$router" iptables -t nat -A POSTROUTING -o outside -j SNAT --to-source 198.51.100.1
ip netns exec "$client" "$python_exe" -m tests.network.lab 198.51.100.1 198.51.100.1
ip netns exec "$client" "$python_exe" -m tests.network.lab 198.51.100.1 192.0.2.10
