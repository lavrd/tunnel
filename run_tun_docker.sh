#!/bin/sh

if [ "$SERVER" == "1" ]; then
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-iface-name tun0 --tun-iface-ip 10.0.0.8/24 &
elif [ "$CLIENT" == "1" ]; then
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-iface-name tun1  --tun-iface-ip 10.0.0.9/24 \
        --udp-server-ip ${SERVER_DOCKER_IP} &
    sleep 1 # to wait until tun1 interface will be up
    ip route add 1.1.1.1/32 dev tun1 &
    ./dns_server
else
    echo "Not a client and not a server."
    exit 1
fi

wait -n
exit $?
