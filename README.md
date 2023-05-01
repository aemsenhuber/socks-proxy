## Name

**socks-proxy** - asynchronous, single-threaded SOCKS proxy

## Synopsis

`socks-proxy [host] port`

## Description

**socks-proxy** implements the SOCKSv5 protocol ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)). It is designed to execute as a single thread and provide connection opening and data forwarding asynchronously.

The program has some limitations:
- No authentication mechanism is provided. You must ensure that only trusted users are able to access the server.
- Only the `bind' command is supported (TCP connection forwarding). Reverse TCP connections and UDP are unsupported.
- [c-ares](https://c-ares.haxx.se/) is used for asynchronous host name resolution. This can be turned off, but the fallback is the C library's name resolver, which is synchronous and may lead to long delays for already established connections.
