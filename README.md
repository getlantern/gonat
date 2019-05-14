This library only works on Linux.

In order to work, this library needs to be able to open raw sockets and update tables.

`sudo setcap CAP_NET_RAW,CAP_NET_ADMIN+ep` might be enough?