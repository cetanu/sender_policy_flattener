# coding=utf-8
import re
from typing import Callable
from functools import partial
from collections.abc import Iterator

from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

# Type Aliases
Token = str
Keyword = str
Prefix = str
MechanismName = str | None
Domain = str
Netblock = str
ProcessedQuery = list[str] | Domain | Netblock | None
MechanismResult = tuple[ProcessedQuery, MechanismName]
Mechanism = Callable[[Token], MechanismResult]


def process_ip(token: Token, keyword: Keyword) -> tuple[Netblock | None, MechanismName]:
    token = token.replace(keyword, "")
    token = token.strip("\"' ")
    try:
        return str(IPAddress(token)), "ip"
    except ValueError:
        return str(IPNetwork(token)), "ip"
    except (AddrFormatError, Exception):
        return None, None


def process_short_alias(
    token: Token, prefix: Prefix
) -> tuple[list[str] | Domain | None, MechanismName]:
    try:
        if ":" in token:
            parts = token.split(":")
            if "/" in parts[1]:
                return parts[1].split("/"), f"{prefix}_domain_prefix"
            return parts[1], f"{prefix}_domain"
        elif "/" in token:
            return token.split("/"), f"{prefix}_prefix"
        elif token == prefix:
            return token, prefix
    except IndexError:
        pass
    return None, None


def process_alias(
    token: Token, keyword: Keyword
) -> tuple[Domain | None, MechanismName]:
    try:
        return token.split(":")[-1], keyword
    except IndexError:
        return None, None


def ptr(token: Token) -> tuple[list[str] | Domain | None, MechanismName]:
    token_part, _type = process_short_alias(token, "ptr")
    if _type:
        return token_part, _type[0:3]
    return token_part, _type


ip4 = partial(process_ip, keyword="ip4:")
ip6 = partial(process_ip, keyword="ip6:")
a = partial(process_short_alias, prefix="a")
mx = partial(process_short_alias, prefix="mx")
include = partial(process_alias, keyword="txt")
exists = partial(process_alias, keyword="exists")


def tokenize(
    answer: str,
) -> Iterator[tuple[str | list[str] | Domain | Netblock | None, MechanismName]]:
    tokens = answer.split()
    for token in tokens:
        # TXT records often contain quotes and will screw with the token.
        token = token.strip("\"' ")
        for pattern, fn in mechanism_mapping.items():
            if re.match(pattern, token):
                yield fn(token)


mechanism_mapping: dict[str, Mechanism] = {
    r"^a[:/]?": a,
    r"^mx[:/]?": mx,
    r"^ptr:?": ptr,
    r"^ip4:": ip4,
    r"^ip6:": ip6,
    r"^include:": include,
    r"^exists:": exists,
}
