#!/bin/sh

# Entrypoint of the Docker image with simple tunnel.
# For client and server sides.

if [ "$SERVER" == "1" ]; then
    # Setup NAT forwarding and routing.
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-device-name tun0 --tun-device-ip 10.0.0.2/24 &
elif [ "$CLIENT" == "1" ]; then
    # If user doesn't provide their own DNS server,
    # just use default one.
    if [ "$DNS_SERVER_IP" == "" ]; then
        DNS_SERVER_IP="1.1.1.1"
    fi
    # Change default nameserver to lookup DNS names.
    echo nameserver ${DNS_SERVER_IP} >/etc/resolv.conf
    ./tunnel run \
        ${TUNNEL_PRIVATE_KEY} ${CLIENT_PUBLIC_KEY} \
        --tun-device-name tun1 --tun-device-ip 10.0.0.3/24 \
        --udp-server-ip ${SERVER_DOCKER_IP} &
    # To wait until tun1 device will be up and running.
    sleep 1
    # Route all traffic to ${DNS_SERVER_IP} to our system tunnel.
    ip route add ${DNS_SERVER_IP}/32 dev tun1 &
    # Start DNS HTTP proxy.
    ./dns_http_proxy
else
    echo "Not a client and not a server."
    exit 1
fi

# Wait until any first process will be stopped.
wait -n
exit $?
