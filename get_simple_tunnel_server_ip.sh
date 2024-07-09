#!/bin/sh

docker container inspect $(docker ps -a | grep -i simple-tunnel-server | awk '{print $1}') | jq -r '.[0].NetworkSettings.Networks.bridge.IPAddress'
