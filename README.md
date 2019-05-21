This library only works on Linux.

In order to work, this library needs to be able to open raw sockets and update the conntrack table
via netlink.

`sudo setcap CAP_NET_RAW,CAP_NET_ADMIN+eip` might be enough?

iptables needs to be configured to drop the outbound RST packets that it would usually create. We do this only
for tcp connections that are already in ESTABLISHED in conntrack. The library manually adds these to conntrack since
we're using raw sockets.

`sudo iptables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL --tcp-flags RST RST -j DROP`

This requires the nf_conntrack module to be installed, along with the conntrack command.

```
modprobe nf_conntrack
modprobe nf_conntrack_ipv4
apt-get install conntrack
```