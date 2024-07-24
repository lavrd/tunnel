#!/bin/sh

if [ "$SERVER" == "1" ]; then
    # Setup NAT forwarding and routing.
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-iface-name tun0 --tun-iface-ip 10.0.0.2/24 &
elif [ "$CLIENT" == "1" ]; then
    # Change default nameserver to lookup DNS names.
    echo nameserver 1.1.1.1 >/etc/resolv.conf
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-iface-name tun1 --tun-iface-ip 10.0.0.3/24 \
        --udp-server-ip ${SERVER_DOCKER_IP} &
    # To wait until tun1 interface will be up and running.
    sleep 1
    # Route all traffic to 1.1.1.1 to our system tunnel.
    ip route add 1.1.1.1/32 dev tun1 &
    ./dns_server
else
    echo "Not a client and not a server."
    exit 1
fi

# Wait until any first process will be stopped.
wait -n
exit $?
