#!/bin/sh

docker container inspect $(docker ps -a | grep -i dns-server | awk '{print $1}') | jq -r '.[0].NetworkSettings.Networks.bridge.IPAddress'
