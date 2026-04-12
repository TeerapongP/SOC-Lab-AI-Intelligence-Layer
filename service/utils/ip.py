from __future__ import annotations

import ipaddress

# RFC-1918, loopback, link-local, unspecified
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_routable(ip: str) -> bool:
    """
    Return True if the IP is globally routable (worth querying CTI for).
    Returns False for RFC-1918, loopback, link-local, and unspecified addresses.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in _PRIVATE_NETWORKS)
