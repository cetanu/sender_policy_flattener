# coding=utf-8
import re
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError


def process_ip(token, keyword):
    token = token.replace(keyword, '')
    token = token.strip('\"\' ')
    try:
        return str(IPAddress(token)), 'ip'
    except ValueError:
        return str(IPNetwork(token)), 'ip'
    except (AddrFormatError, Exception):
        return None, None


def process_short_alias(token, prefix):
    try:
        if ':' in token:
            token = token.split(':')
            if '/' in token[1]:
                return token[1].split('/'), '{0}_domain_prefix'.format(prefix)
            return token[1], '{0}_domain'.format(prefix)
        elif '/' in token:
            return token.split('/'), '{0}_prefix'.format(prefix)
        elif token == prefix:
            return token, prefix
    except IndexError:
        pass
    return None, None


def process_alias(token, keyword):
    try:
        return token.split(':')[-1], keyword
    except IndexError:
        return None, None


def ip4(token):
    return process_ip(token, 'ip4:')


def ip6(token):
    return process_ip(token, 'ip6:')


def a(token):
    return process_short_alias(token, 'a')


def mx(token):
    return process_short_alias(token, 'mx')


def ptr(token):
    token, _type = process_short_alias(token, 'ptr')
    return token, _type[0:3]


def include(token):
    return process_alias(token, 'txt')


def exists(token):
    return process_alias(token, 'exists')


def tokenize(answer):
    tokens = answer.split()
    for token in tokens:
        # TXT records often contain quotes and will screw with the token.
        token = token.strip('\"\' ')
        for pattern, fn in mechanism_mapping.items():
            if re.match(pattern, token):
                yield fn(token)


mechanism_mapping = {
    r'^a[:/]?': a,
    r'^mx[:/]?': mx,
    r'^ptr:?': ptr,
    r'^ip4:': ip4,
    r'^ip6:': ip6,
    r'^include:': include,
    r'^exists:': exists,
}
