# coding=utf-8

from dns import resolver  # dnspython/3
from sender_policy_flattener.formatting import wrap_in_spf_tokens, ips_to_spf_strings, fit_bytes
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import *


handle_tokens = {
    'ip': handle_ip,
    'mx': handle_mx,
    'mx_prefix': handle_mx_prefix,
    'mx_domain': handle_mx_domain,
    'mx_domain_prefix': handle_mx_domain_prefix,
    'a': handle_a,
    'a_domain': handle_a_domain,
    'a_prefix': handle_a_prefix,
    'a_domain_prefix': handle_a_domain_prefix,
    'ptr': handle_ptr,
    'exists': handle_exists,
}

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
        answers = ns.query(rrname, rrtype)
    except Exception as err:
        print(repr(err), rrname, rrtype)
    else:
        answer = ' '.join(answers)
        for pair in tokenize(answer):
            rname, rtype = pair
            if rtype == 'txt':
                for ip in crawl(rname, 'txt', domain, ns):
                    yield ip
                continue
            for ip in handle_tokens[rtype](rname, domain, ns):
                yield ip
