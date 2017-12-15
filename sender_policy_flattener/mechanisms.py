# coding=utf-8
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError


def tokenize(answer):
    tokens = answer.split()
    for token in tokens:
        if any([token.startswith('a:'), token.startswith('a/'), token == 'a']):
            yield a(token)
        elif any([token.startswith('mx:'), token.startswith('mx/'), token == 'mx']):
            yield mx(token)
        elif any([token.startswith('ptr:'), token == 'ptr']):
            yield ptr(token)
        elif 'ip4:' in token:
            yield ip4(token)
        elif 'ip6:' in token:
            yield ip6(token)
        elif 'include:' in token:
            yield include(token)
        elif 'exists:' in token:
            yield exists(token)


def ip4(token):
    token = token.lstrip('ip4:')
    try:
        return str(IPAddress(token)), 'ip'
    except ValueError:
        return str(IPNetwork(token)), 'ip'
    except (AddrFormatError, Exception):
        return None, None


def ip6(token):
    token = token.lstrip('ip6:')
    try:
        return str(IPAddress(token)), 'ip'
    except ValueError:
        return str(IPNetwork(token)), 'ip'
    except (AddrFormatError, Exception):
        return None, None


def a(token):
    if ':' in token:
        token = token.split(':')
        try:
            if '/' in token[1]:
                return token[1].split('/'), 'a_domain_prefix'
            return token[1], 'a_domain'
        except IndexError:
            return None, None
    elif '/' in token:
        try:
            return token.split('/'), 'a_prefix'
        except IndexError:
            return None, None
    elif token == 'a':
        return token, 'a'


def mx(token):
    if ':' in token:
        token = token.split(':')
        try:
            if '/' in token[1]:
                return token[1].split('/'), 'mx_domain_prefix'
            return token[1], 'mx_domain'
        except IndexError:
            return None, None
    elif '/' in token:
        try:
            return token.split('/'), 'mx_prefix'
        except IndexError:
            return None, None
    elif token == 'mx':
        return token, 'mx'


def ptr(token):
    if ':' in token:
        try:
            return token.split(':')[-1], 'ptr'
        except IndexError:
            return None, None
    elif token == 'ptr':
        return token, 'ptr'


def include(token):
    try:
        return token.split(':')[-1], 'txt'
    except IndexError:
        return None, None


def exists(token):
    try:
        return token.split(':')[-1], 'exists'
    except IndexError:
        return None, None
