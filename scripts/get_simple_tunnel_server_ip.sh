#!/bin/sh

# We need this script to find IP address of the simple tunnel server inside the container.

docker container inspect \
    $(docker ps -a | grep -i simple-tunnel-server | awk '{print $1}') |
    jq -r '.[0].NetworkSettings.Networks.bridge.IPAddress'
