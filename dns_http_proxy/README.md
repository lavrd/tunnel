# DNS HTTP proxy

In order to access tunnels inside Docker containers we need some kind of server which can be used by containers open ports. After direct request to this DNS HTTP proxy server, tunnel inside container can hijack packets and process them.
