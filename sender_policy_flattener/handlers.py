# coding=utf-8
import asyncio
from collections.abc import AsyncIterator
from typing import Callable

import dns.asyncresolver
from netaddr import IPNetwork, IPAddress

from sender_policy_flattener import dns_utils

# Type Aliases
Domain = str
Mechanism = str
Netblock = str
HandlerResponse = AsyncIterator[str | IPNetwork | IPAddress | Netblock]
Handler = Callable[[str, Domain, dns.asyncresolver.Resolver], HandlerResponse]
PrefixHandler = Callable[
    [list[str], Domain, dns.asyncresolver.Resolver], HandlerResponse
]


async def handle_ip(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[Netblock]:
    yield name


async def _mx_ips(
    target: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPAddress]:
    answers = await dns_utils.resolve(ns, target, "mx")
    exchanges = [str(mailexchange.exchange) for mailexchange in answers]
    results = await asyncio.gather(
        *(dns_utils.resolve(ns, exchange, "a") for exchange in exchanges)
    )
    for ips in results:
        for ip in ips:
            yield IPAddress(ip.address)


async def handle_mx(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPAddress]:
    async for ip in _mx_ips(domain, ns):
        yield ip


async def handle_mx_domain(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPAddress]:
    async for ip in _mx_ips(name, ns):
        yield ip


async def handle_mx_prefix(
    name: list[str], domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPNetwork]:
    _name, prefix = name
    async for ip in _mx_ips(domain, ns):
        yield IPNetwork(f"{ip}/{prefix}")


async def handle_mx_domain_prefix(
    name: list[str], domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPNetwork]:
    _name, prefix = name
    async for ip in _mx_ips(_name, ns):
        yield IPNetwork(f"{ip}/{prefix}")


async def handle_a(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPAddress]:
    answers = await dns_utils.resolve(ns, domain, "a")
    for ip in answers:
        yield IPAddress(ip.address)


async def handle_a_domain(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPAddress]:
    answers = await dns_utils.resolve(ns, name, "a")
    for ip in answers:
        yield IPAddress(ip.address)


async def handle_a_prefix(
    name: list[str], domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPNetwork]:
    _name, prefix = name
    answers = await dns_utils.resolve(ns, domain, "a")
    for ip in answers:
        yield IPNetwork(f"{ip}/{prefix}")


async def handle_a_domain_prefix(
    name: list[str], domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[IPNetwork]:
    _name, prefix = name
    answers = await dns_utils.resolve(ns, _name, "a")
    for ip in answers:
        yield IPNetwork(f"{ip}/{prefix}")


async def handle_ptr(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[str]:
    yield f"ptr:{name}"


async def handle_exists(
    name: str, domain: Domain, ns: dns.asyncresolver.Resolver
) -> AsyncIterator[str]:
    yield f"exists:{name}"


handler_mapping: dict[str, Handler] = {
    "ip": handle_ip,
    "mx": handle_mx,
    "mx_domain": handle_mx_domain,
    "a": handle_a,
    "a_domain": handle_a_domain,
    "ptr": handle_ptr,
    "exists": handle_exists,
}


prefix_handler_mapping: dict[str, PrefixHandler] = {
    "mx_prefix": handle_mx_prefix,
    "mx_domain_prefix": handle_mx_domain_prefix,
    "a_prefix": handle_a_prefix,
    "a_domain_prefix": handle_a_domain_prefix,
}

# Used for top-level "sending domains" entries, e.g. {"example.com": "a"}.
# These always carry an explicit target name, so "a"/"mx" here mean
# "resolve this named domain's records" (the *_domain handlers), unlike
# the bare "a"/"mx" SPF mechanisms which mean "resolve the current domain".
top_level_handler_mapping: dict[str, Handler] = {
    "a": handle_a_domain,
    "mx": handle_mx_domain,
    "ptr": handle_ptr,
    "exists": handle_exists,
    "ip": handle_ip,
}
