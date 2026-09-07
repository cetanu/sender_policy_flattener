# coding=utf-8
import hashlib
import sys
from collections.abc import Iterator, Iterable
from difflib import HtmlDiff

from netaddr import IPSet, IPNetwork, AddrFormatError

# Type Aliases
Domain = str
SPFRecord = str
BindRecord = str
EmailBody = str
IPAddress = str
Netblock = str
SourceMap = dict[Netblock, list[str]]

_diff_style = """
    <style type="text/css">
        body {font-family: "Helvetica Neue Light", "Lucida Grande", "Calibri", "Arial", sans-serif;}
        a {text-decoration: none; color: royalblue; padding: 5px;}
        a:visited {color: royalblue}
        a:hover {background-color: royalblue; color: white;}
        h1 {
            font-family: "Helvetica Neue Light", "Lucida Grande", "Calibri", "Arial", sans-serif;
            font-size: 14pt;
        }
        table.diff {border: 1px solid black;}
        td {padding: 5px;}
        td.diff_header {text-align:right}
        .diff_header {background-color:#e0e0e0}
        .diff_next {background-color:#c0c0c0}
        .diff_add {background-color:#aaffaa}
        .diff_chg {background-color:#ffff77}
        .diff_sub {background-color:#ffaaaa}
    </style>
    """


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


def _bind_lines(curr_addrs: list[SPFRecord]) -> list[BindRecord]:
    bindformat: list[BindRecord] = []
    for record in curr_addrs:
        bindformat.extend(format_rrecord_value_for_bind(record))

    count = 0
    for index, chunk in enumerate(bindformat):
        if "(" in chunk:
            bindformat[index] = "@ IN TXT (" if count == 0 else f"spf{count} IN TXT ("
            count += 1
    return bindformat


def format_records_for_email(curr_addrs: list[SPFRecord]) -> EmailBody:
    bindformat = _bind_lines(curr_addrs)
    return (
        "<p><h1>BIND compatible format:</h1><pre>"
        + "\n".join(bindformat)
        + "</pre></p>"
    )


def format_records_as_bind_text(curr_addrs: list[SPFRecord]) -> str:
    """Plain (non-HTML) BIND zonefile snippet, for writing straight to disk."""
    return "\n".join(_bind_lines(curr_addrs))


def _strip_ip_prefix(token: SPFRecord) -> Netblock:
    for prefix in ("ip4:", "ip6:"):
        if token.startswith(prefix):
            return token[len(prefix) :]
    return token


def attribute_sources(ip_token: Netblock, sources: SourceMap) -> list[str]:
    """Which include(s) a flattened IP/CIDR came from, per `sources`.

    A direct hit covers the common case (a bare host address survives
    flattening unchanged), but CIDR compaction can also merge netblocks
    from several includes into one supernet that happens to match another
    include's own raw netblock exactly — so a direct hit doesn't rule out
    other includes. Always add any raw netblock swallowed by `ip_token`.
    """
    if not sources:
        return []
    matches: set[str] = set(sources.get(ip_token, []))
    try:
        target = IPSet([ip_token])
    except (AddrFormatError, ValueError):
        return sorted(matches)
    for raw_ip, srcs in sources.items():
        try:
            if IPSet([raw_ip]).issubset(target):
                matches.update(srcs)
        except (AddrFormatError, ValueError):
            continue
    return sorted(matches)


def _annotate_with_source(token: SPFRecord, sources: SourceMap) -> SPFRecord:
    labels = attribute_sources(_strip_ip_prefix(token), sources)
    if not labels:
        return token
    return f"{token}  ; from {','.join(labels)}"


def render_diff_html(
    zone: Domain,
    prev_addrs: list[SPFRecord],
    curr_addrs: list[SPFRecord],
    prev_sources: SourceMap | None = None,
    curr_sources: SourceMap | None = None,
) -> tuple[EmailBody, EmailBody]:
    """Renders a standalone HTML page: BIND format + an old/new records diff.

    Returns (html, bindformat) — bindformat is also handed back since callers
    (email + on-disk reports) both want it, and it's already computed here.

    `prev_sources`/`curr_sources` map a raw IP/netblock to the include(s) it
    was resolved from, so the rendered diff can show which include a changed
    address came from.
    """
    bindformat = format_records_for_email(curr_addrs)
    prev_addrs_str = " ".join(prev_addrs)
    curr_addrs_str = " ".join(curr_addrs)
    prev = sorted([s for s in prev_addrs_str.split() if "ip" in s])
    curr = sorted([s for s in curr_addrs_str.split() if "ip" in s])
    if prev_sources:
        prev = [_annotate_with_source(s, prev_sources) for s in prev]
    if curr_sources:
        curr = [_annotate_with_source(s, curr_sources) for s in curr]

    diff = HtmlDiff()
    table = diff.make_table(
        fromlines=prev, tolines=curr, fromdesc="Old records", todesc="New records"
    )

    header = f"<h1>Diff for {zone}</h1>"
    html = _diff_style + bindformat + header + table
    return html, bindformat


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
