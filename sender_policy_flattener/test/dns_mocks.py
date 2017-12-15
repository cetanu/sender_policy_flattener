# coding=utf-8

first_answer = ' '.join([
    '"v=spf1',
    'a:test.fake',
    'mx:test.fake',
    'ptr:10.0.0.1.in-addr.arpa',
    'include:spf.fake.test',
    'ip6:2001:4860:4000::',
    'ip6:2404:6800:4000::/36',
    'ip4:10.0.0.1',
    'ip4:10.0.0.0/24',
    'ip4:10.0.0.1/32',
    'exists:fake.test',
    '-all"',
])

dns_responses = {
    'txt': {
        'test.com': [first_answer],
        'spf.fake.test': [
            'ip4:172.16.0.1',
            'ip4:172.16.0.0/24',
            'ip4:172.16.0.1/32',
        ]
    },
    'a': {
        'test.fake': [
            '10.0.0.10',
            '10.0.0.11'
        ],
        'mx.test.fake': [
            '10.0.0.12',
            '10.0.0.13'
        ],
    },
    'mx': {
        'test.fake': [
            'mx.test.fake'
        ]
    },
    'cname': {
        'test.fake': [
            '10.0.0.14',
            '10.0.0.15'
        ]
    },
    'ptr': {
        '10.0.0.1.in-addr.arpa': [
            'fwd.test.fake'
        ]
    },
}
