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


handler_mapping = {
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
