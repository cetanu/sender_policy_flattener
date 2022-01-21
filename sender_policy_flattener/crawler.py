# coding=utf-8

from dns import resolver  # dnspython/3
from dns.resolver import NXDOMAIN
from dns.name import from_text
from sender_policy_flattener.formatting import (
    wrap_in_spf_tokens,
    ips_to_spf_strings,
    fit_bytes,
)
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import handler_mapping

default_resolvers = resolver.Resolver()


def spf2ips(records, domain, resolvers=default_resolvers):
    ips = set()
    for rrecord, rdtype in records.items():
        for ip in crawl(rrecord, rdtype, domain, resolvers):
            ips.add(ip)
    ips = ips_to_spf_strings(ips)
    ipv4blocks, last_record = fit_bytes(ips)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]


def crawl(rrname, rrtype, domain, ns=default_resolvers):
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
                for ip in crawl(rname, "txt", domain, ns):
                    yield ip
                continue
            try:
                for ip in handler_mapping[rtype](rname, domain, ns):
                    yield ip
            except NXDOMAIN as e:
                print(e)
