# coding=utf-8
from netaddr import IPNetwork, IPAddress


def handle_ip(name, domain, ns):
    yield name


def handle_mx(name, domain, ns):
    answers = ns.query(domain, 'mx')
    for mailexchange in answers:
        ips = ns.query(mailexchange, 'a')
        for ip in ips:
            yield IPAddress(ip)


def handle_mx_domain(name, domain, ns):
    answers = ns.query(name, 'mx')
    for mailexchange in answers:
        ips = ns.query(mailexchange, 'a')
        for ip in ips:
            yield IPAddress(ip)


def handle_mx_prefix(name, domain, ns):
    _name, prefix = name
    answers = ns.query(domain, 'mx')
    for mailexchange in answers:
        ips = ns.query(mailexchange, 'a')
        for ip in ips:
            yield IPNetwork('{0}/{1}'.format(ip, prefix))


def handle_mx_domain_prefix(name, domain, ns):
    _name, prefix = name
    answers = ns.query(_name, 'mx')
    for mailexchange in answers:
        ips = ns.query(mailexchange, 'a')
        for ip in ips:
            yield IPNetwork('{0}/{1}'.format(ip, prefix))


def handle_a(name, domain, ns):
    answers = ns.query(domain, 'a')
    for ip in answers:
        yield IPAddress(ip)


def handle_a_domain(name, domain, ns):
    answers = ns.query(name, 'a')
    for ip in answers:
        yield IPAddress(ip)


def handle_a_prefix(name, domain, ns):
    _name, prefix = name
    answers = ns.query(domain, 'a')
    for ip in answers:
        yield IPNetwork('{0}/{1}'.format(ip, prefix))


def handle_a_domain_prefix(name, domain, ns):
    _name, prefix = name
    answers = ns.query(_name, 'a')
    for ip in answers:
        yield IPNetwork('{0}/{1}'.format(ip, prefix))


def handle_ptr(name, domain, ns):
    yield 'ptr:{0}'.format(name)


def handle_exists(name, domain, ns):
    yield 'exists:{0}'.format(name)
