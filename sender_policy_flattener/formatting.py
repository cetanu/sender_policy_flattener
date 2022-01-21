# coding=utf-8
import hashlib
import sys
from netaddr import IPSet, IPNetwork, AddrFormatError


def wrap_in_spf_tokens(domain, ipv4blocks, last_record):
    for spf_num, spf_set in enumerate(ipv4blocks):
        spf_set = " ".join(spf_set)
        if spf_num == last_record:
            spfrecord = "v=spf1 {0} -all".format(spf_set)
        else:
            spfrecord = "v=spf1 {0} include:spf{1}.{2} -all".format(
                spf_set, spf_num + 1, domain
            )
        yield spfrecord


def format_rrecord_value_for_bind(spfrec):
    spfrec = spfrec.split()
    yield "( "
    while spfrec:
        line, end = '"', '"'
        try:
            for i in range(4):
                line += spfrec.pop(0) + " "
        except IndexError:
            end = '"'
        finally:
            yield line + end
    yield " )"


def sequence_hash(iterable):
    flat_sorted_sequence = " ".join(
        sorted([token for string in iterable for token in string.split()])
    )
    return hashlib.sha256(flat_sorted_sequence.encode()).hexdigest()


def format_records_for_email(curr_addrs):
    bindformat = list()
    for record in curr_addrs:
        bindformat += format_rrecord_value_for_bind(record)

    count = 0
    for index, chunk in enumerate(bindformat):
        if "(" in chunk:
            bindformat[index] = (
                "@ IN TXT (" if count == 0 else "spf{0} IN TXT (".format(count)
            )
            count += 1

    bindformat = (
        "<p><h1>BIND compatible format:</h1><pre>"
        + "\n".join(bindformat)
        + "</pre></p>"
    )
    return bindformat


def ips_to_spf_strings(ips):
    other_tokens = list()
    for index, ip in enumerate(ips):
        try:
            IPNetwork(ip)
        except AddrFormatError:
            other_tokens.append(ip)
    for token in other_tokens:
        ips.remove(token)
    ips = [str(i) for i in IPSet(ips).iter_cidrs()]
    ips = ["ip6:" + ip if ":" in ip else "ip4:" + ip.replace("/32", "") for ip in ips]
    return ips + other_tokens


def spf_record_len(addresses):
    quote_allowance = '" "' * (len(addresses) // 4)
    return sys.getsizeof(
        "v=spf1 {addresses} {quotes} include:spf1.example.domain.com -all".format(
            addresses=" ip4:".join(addresses), quotes=quote_allowance
        )
    )


def fit_bytes(ips, _bytes=450):
    """https://tools.ietf.org/html/rfc4408"""
    blocks = [sorted(set(ips))]
    for index, addresses in enumerate(blocks):
        while spf_record_len(addresses) >= _bytes:
            overflow = blocks[index].pop()
            try:
                blocks[index + 1]
            except IndexError:
                blocks.append(list())
            finally:
                blocks[index + 1].append(overflow)
    last_index = len(blocks) - 1
    return blocks, last_index
