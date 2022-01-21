# coding=utf-8
import re
from functools import partial
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError


def process_ip(token, keyword):
    token = token.replace(keyword, "")
    token = token.strip("\"' ")
    try:
        return str(IPAddress(token)), "ip"
    except ValueError:
        return str(IPNetwork(token)), "ip"
    except (AddrFormatError, Exception):
        return None, None


def process_short_alias(token, prefix):
    try:
        if ":" in token:
            token = token.split(":")
            if "/" in token[1]:
                return token[1].split("/"), "{0}_domain_prefix".format(prefix)
            return token[1], "{0}_domain".format(prefix)
        elif "/" in token:
            return token.split("/"), "{0}_prefix".format(prefix)
        elif token == prefix:
            return token, prefix
    except IndexError:
        pass
    return None, None


def process_alias(token, keyword):
    try:
        return token.split(":")[-1], keyword
    except IndexError:
        return None, None


def ptr(token):
    token, _type = process_short_alias(token, "ptr")
    return token, _type[0:3]


ip4 = partial(process_ip, keyword="ip4:")
ip6 = partial(process_ip, keyword="ip6:")
a = partial(process_short_alias, prefix="a")
mx = partial(process_short_alias, prefix="mx")
include = partial(process_alias, keyword="txt")
exists = partial(process_alias, keyword="exists")


def tokenize(answer):
    tokens = answer.split()
    for token in tokens:
        # TXT records often contain quotes and will screw with the token.
        token = token.strip("\"' ")
        for pattern, fn in mechanism_mapping.items():
            if re.match(pattern, token):
                yield fn(token)


mechanism_mapping = {
    r"^a[:/]?": a,
    r"^mx[:/]?": mx,
    r"^ptr:?": ptr,
    r"^ip4:": ip4,
    r"^ip6:": ip6,
    r"^include:": include,
    r"^exists:": exists,
}
