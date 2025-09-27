# coding=utf-8
from typing import Callable
from collections.abc import Iterator

from dns.name import from_text
from dns.resolver import Resolver
from netaddr import IPNetwork, IPAddress

# Type Aliases
Domain = str
Mechanism = str
Netblock = str
HandlerResponse = Iterator[str | IPNetwork | IPAddress | Netblock]
Handler = Callable[[str, Domain, Resolver], HandlerResponse]
PrefixHandler = Callable[[list[str], Domain, Resolver], HandlerResponse]


def handle_ip(name: str, domain: Domain, ns: Resolver) -> Iterator[Netblock]:  # pyright: ignore[reportUnusedParameter]
    yield name


def handle_mx(name: str, domain: Domain, ns: Resolver) -> Iterator[IPAddress]:  # pyright: ignore[reportUnusedParameter]
    answers = ns.query(from_text(domain), "mx")
    for mailexchange in answers:
        ips = ns.query(mailexchange.exchange, "a")
        for ip in ips:
            yield IPAddress(ip.address)


def handle_mx_domain(name: str, domain: Domain, ns: Resolver) -> Iterator[IPAddress]:  # pyright: ignore[reportUnusedParameter]
    answers = ns.query(from_text(name), "mx")
    for mailexchange in answers:
        ips = ns.query(mailexchange, "a")
        for ip in ips:
            yield IPAddress(ip.address)


def handle_mx_prefix(
    name: list[str], domain: Domain, ns: Resolver
) -> Iterator[IPNetwork]:
    _name, prefix = name
    answers = ns.query(from_text(domain), "mx")
    for mailexchange in answers:
        ips = ns.query(mailexchange.exchange, "a")
        for ip in ips:
            yield IPNetwork(f"{ip}/{prefix}")


def handle_mx_domain_prefix(
    name: list[str],
    domain: Domain,  # pyright: ignore[reportUnusedParameter]
    ns: Resolver,
) -> Iterator[IPNetwork]:
    _name, prefix = name
    answers = ns.query(from_text(_name), "mx")
    for mailexchange in answers:
        ips = ns.query(mailexchange, "a")
        for ip in ips:
            yield IPNetwork(f"{ip}/{prefix}")


def handle_a(name: str, domain: Domain, ns: Resolver) -> Iterator[IPAddress]:  # pyright: ignore[reportUnusedParameter]
    answers = ns.query(from_text(domain), "a")
    for ip in answers:
        yield IPAddress(ip.address)


def handle_a_domain(name: str, domain: Domain, ns: Resolver) -> Iterator[IPAddress]:  # pyright: ignore[reportUnusedParameter]
    answers = ns.query(from_text(name), "a")
    for ip in answers:
        yield IPAddress(ip.address)


def handle_a_prefix(
    name: list[str], domain: Domain, ns: Resolver
) -> Iterator[IPNetwork]:
    _name, prefix = name
    answers = ns.query(from_text(domain), "a")
    for ip in answers:
        yield IPNetwork(f"{ip}/{prefix}")


def handle_a_domain_prefix(
    name: list[str],
    domain: Domain,  # pyright: ignore[reportUnusedParameter]
    ns: Resolver,
) -> Iterator[IPNetwork]:
    _name, prefix = name
    answers = ns.query(from_text(_name), "a")
    for ip in answers:
        yield IPNetwork(f"{ip}/{prefix}")


def handle_ptr(name: str, domain: Domain, ns: Resolver) -> Iterator[str]:  # pyright: ignore[reportUnusedParameter]
    yield f"ptr:{name}"


def handle_exists(name: str, domain: Domain, ns: Resolver) -> Iterator[str]:  # pyright: ignore[reportUnusedParameter]
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
