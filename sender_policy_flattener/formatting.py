# coding=utf-8
import hashlib
import sys
from collections.abc import Iterator, Iterable

from netaddr import IPSet, IPNetwork, AddrFormatError

# Type Aliases
Domain = str
SPFRecord = str
BindRecord = str
EmailBody = str
IPAddress = str
Netblock = str


def wrap_in_spf_tokens(
    domain: Domain, ipv4blocks: list[list[Netblock]], last_record: int
) -> Iterator[SPFRecord]:
    for spf_num, spf_set in enumerate(ipv4blocks):
        spf_set_str = " ".join(spf_set)
        if spf_num == last_record:
            spfrecord = f"v=spf1 {spf_set_str} -all"
        else:
            spfrecord = f"v=spf1 {spf_set_str} include:spf{spf_num + 1}.{domain} -all"
        yield spfrecord


def format_rrecord_value_for_bind(spfrec: SPFRecord) -> Iterator[BindRecord]:
    spfrec_list = spfrec.split()
    yield "( "
    while spfrec_list:
        line, end = '"', '"'
        try:
            for _ in range(4):
                line += spfrec_list.pop(0) + " "
        except IndexError:
            end = '"'
        finally:
            yield line + end
    yield " )"


def sequence_hash(iterable: Iterable[str]) -> str:
    flat_sorted_sequence = " ".join(
        sorted([token for string in iterable for token in string.split()])
    )
    return hashlib.sha256(flat_sorted_sequence.encode()).hexdigest()


def format_records_for_email(curr_addrs: list[SPFRecord]) -> EmailBody:
    bindformat: list[BindRecord] = []
    for record in curr_addrs:
        bindformat.extend(format_rrecord_value_for_bind(record))

    count = 0
    for index, chunk in enumerate(bindformat):
        if "(" in chunk:
            bindformat[index] = "@ IN TXT (" if count == 0 else f"spf{count} IN TXT ("
            count += 1

    return (
        "<p><h1>BIND compatible format:</h1><pre>"
        + "\n".join(bindformat)
        + "</pre></p>"
    )


def ips_to_spf_strings(ips: set[IPAddress | Netblock]) -> list[str]:
    other_tokens: list[str] = []
    for ip in list(ips):
        try:
            _ = IPNetwork(ip)
        except AddrFormatError:
            other_tokens.append(ip)
            ips.remove(ip)
    ip_list = [str(i) for i in IPSet(ips).iter_cidrs()]
    ip_list = [
        "ip6:" + ip if ":" in ip else "ip4:" + ip.replace("/32", "") for ip in ip_list
    ]
    return ip_list + other_tokens


def spf_record_len(addresses: list[Netblock]) -> int:
    quote_allowance = '" "' * (len(addresses) // 4)
    return sys.getsizeof(
        f"v=spf1 {' ip4:'.join(addresses)} {quote_allowance} include:spf1.example.domain.com -all"
    )


def fit_bytes(ips: list[str], _bytes: int = 450) -> tuple[list[list[str]], int]:
    """https://tools.ietf.org/html/rfc4408"""
    blocks: list[list[str]] = [sorted(set(ips))]
    for index, addresses in enumerate(blocks):
        while spf_record_len(addresses) >= _bytes:
            overflow = blocks[index].pop()
            try:
                blocks[index + 1]
            except IndexError:
                blocks.append([])
            finally:
                blocks[index + 1].append(overflow)
    last_index = len(blocks) - 1
    return blocks, last_index
