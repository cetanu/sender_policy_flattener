# coding=utf-8
"""
A script that crawls and compacts SPF records into IP networks.
This helps to avoid exceeding the DNS lookup limit of the Sender Policy Framework (SPF)
https://tools.ietf.org/html/rfc7208#section-4.6.4
"""

import asyncio
from collections.abc import AsyncIterator
from typing import Callable

import dns.asyncresolver
import structlog
from dns.resolver import NXDOMAIN, NoAnswer

from sender_policy_flattener import dns_utils
from sender_policy_flattener.formatting import (
    wrap_in_spf_tokens,
    ips_to_spf_strings,
    fit_bytes,
)
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import (
    handler_mapping,
    prefix_handler_mapping,
    top_level_handler_mapping,
)

# Type Aliases
Domain = str
RRType = str
Record = str
Netblock = str

log = structlog.get_logger(__name__)

default_resolvers = dns.asyncresolver.Resolver()


async def crawl(
    rrname: Record,
    rrtype: RRType,
    domain: Domain,
    ns: dns.asyncresolver.Resolver = default_resolvers,
    sources_out: dict[Netblock, set[Record]] | None = None,
) -> AsyncIterator[Netblock]:
    def _tag(ip: Netblock, source: Record) -> Netblock:
        if sources_out is not None:
            sources_out.setdefault(ip, set()).add(source)
        return ip

    rrtype = rrtype.lower()
    if rrtype != "txt":
        # Top-level "sending domains" entries carry an explicit target name
        # (e.g. {"example.com": "a"}), unlike SPF mechanisms embedded in a
        # TXT record's text, which are resolved by tokenizing below.
        try:
            async for result in top_level_handler_mapping[rrtype](rrname, domain, ns):
                yield _tag(str(result), rrname)
        except (NXDOMAIN, NoAnswer) as e:
            log.warning("dns_lookup_failed", rrname=rrname, rrtype=rrtype, error=str(e))
        return
    try:
        answers = await dns_utils.resolve(ns, rrname, rrtype)
    except Exception as err:
        log.warning("dns_lookup_failed", rrname=rrname, rrtype=rrtype, error=repr(err))
    else:
        answer = " ".join([str(a) for a in answers])
        for pair in tokenize(answer):
            rname, rtype = pair
            if rtype is None:
                continue
            if rtype == "txt":
                if isinstance(rname, list):
                    rname = "".join(rname)
                if rname is None:
                    continue
                async for ip in crawl(rname, "txt", domain, ns, sources_out):
                    yield ip
                continue
            try:
                if rname is None:
                    continue
                if isinstance(rname, list):
                    async for result in prefix_handler_mapping[rtype](
                        rname, domain, ns
                    ):
                        yield _tag(str(result), rrname)
                else:
                    async for result in handler_mapping[rtype](rname, domain, ns):
                        yield _tag(str(result), rrname)
            except (NXDOMAIN, NoAnswer) as e:
                log.warning("dns_lookup_failed", rname=rname, rtype=rtype, error=str(e))


async def spf2ips(
    records: dict[Record, RRType],
    domain: Domain,
    resolvers: dns.asyncresolver.Resolver = default_resolvers,
    crawler: Callable[
        ...,
        AsyncIterator[Netblock],
    ] = crawl,
    static_ips: list[str] | None = None,
    sources_out: dict[Netblock, set[Record]] | None = None,
) -> list[str]:
    ips: set[Netblock] = set()
    if static_ips:
        for ip in static_ips:
            ips.add(ip)
            if sources_out is not None:
                sources_out.setdefault(ip, set()).add("static")

    async def _crawl_one(rrecord: Record, rdtype: RRType) -> set[Netblock]:
        return {
            ip
            async for ip in crawler(
                rrecord, rdtype, domain, resolvers, sources_out=sources_out
            )
        }

    results = await asyncio.gather(
        *(_crawl_one(rrecord, rdtype) for rrecord, rdtype in records.items())
    )
    for result in results:
        ips |= result

    spf_strings = ips_to_spf_strings(ips)
    ipv4blocks, last_record = fit_bytes(spf_strings)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]
