# coding=utf-8

first_answer = ' '.join([
    '"v=spf1',
    'a:test.fake',
    'a/26',
    'mx:test.fake',
    'mx:test.fake/27',
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

lots_of_blocks = ['ip4:{0}.{1}.{2}.{3}/{4}'.format(o1, o2, o3, o4, p)
                  for o1 in range(5, 10)
                  for o2 in range(1, 5)
                  for o3 in range(1, 5)
                  for o4 in range(1, 5)
                  for p in range(26, 31)]
large_answer = '"v=spf1 {0} -all"'.format(' '.join(lots_of_blocks))

dns_responses = {
    'txt': {
        'test.com': [first_answer],
        'galactus.com': [large_answer],
        'spf.fake.test': ['v=spf1 ip4:172.16.0.1 ip4:172.16.0.0/24 ip4:172.16.0.1/32'],
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
        'test.com': [
            '192.168.0.1'
        ],
        'mx.test.com': [
            '192.168.0.10'
        ]
    },
    'mx': {
        'test.fake': [
            'mx.test.fake'
        ],
        'test.com': [
            'mx.test.com'
        ]
    },
    'ptr': {
        '10.0.0.1.in-addr.arpa': [
            'fwd.test.fake'
        ]
    },
}
