This library only works on Linux.

In order to work, this library needs to be able to open raw sockets and update the conntrack table
via netlink.

`sudo setcap CAP_NET_RAW,CAP_NET_ADMIN+ep` might be enough?

iptables needs to be configured to drop the outbound RST packets that it would usually create. We do this only
for tcp connections that are already in conntrack (which are added to conntrack by the library itself).

`sudo iptables -A OUTPUT -p tcp -m conntrack --ctproto tcp --ctdir ORIGINAL --tcp-flags RST RST -j DROP`