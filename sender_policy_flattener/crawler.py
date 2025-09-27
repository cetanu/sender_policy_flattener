# coding=utf-8

from collections.abc import Iterator
from typing import Callable

from dns import resolver  # dnspython/3
from dns.resolver import NXDOMAIN, NoAnswer, Resolver
from dns.name import from_text
from sender_policy_flattener.formatting import (
    wrap_in_spf_tokens,
    ips_to_spf_strings,
    fit_bytes,
)
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import (
    handler_mapping, 
    prefix_handler_mapping,
)

# Type Aliases
Domain = str
RRType = str
Record = str
Netblock = str

default_resolvers = resolver.Resolver()


def crawl(
    rrname: Record, rrtype: RRType, domain: Domain, ns: Resolver = default_resolvers
) -> Iterator[Netblock]:
    try:
        answers = ns.query(from_text(rrname), rrtype)
    except Exception as err:
        print(repr(err), rrname, rrtype)
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
                for ip in crawl(rname, "txt", domain, ns):
                    yield ip
                continue
            try:
                if rname is None:
                    continue
                if isinstance(rname, list):
                    for result in prefix_handler_mapping[rtype](rname, domain, ns):
                        yield str(result)
                else:
                    for result in handler_mapping[rtype](rname, domain, ns):
                        yield str(result)
            except (NXDOMAIN, NoAnswer) as e:
                print(e)


def spf2ips(
    records: dict[Record, RRType],
    domain: Domain,
    resolvers: Resolver = default_resolvers,
    crawler: Callable[[
        Record, RRType, Domain, Resolver
    ], Iterator[Netblock]] = crawl,
) -> list[str]:
    ips: set[Netblock] = set()
    for rrecord, rdtype in records.items():
        for ip in crawler(rrecord, rdtype, domain, resolvers):
            ips.add(ip)
    spf_strings = ips_to_spf_strings(ips)
    ipv4blocks, last_record = fit_bytes(spf_strings)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]
