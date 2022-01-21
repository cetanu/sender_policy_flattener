# coding=utf-8

test_com_netblocks = [
    # a:test.fake
    "10.0.0.10",
    "10.0.0.11",
    # a/26
    "192.168.0.1/26",
    # mx:test.fake
    "10.0.0.12",
    "10.0.0.13",
    # mx:test.fake/27
    "10.0.0.12/27",
    "10.0.0.13/27",
    # ptr:10.0.0.1.in-addr.arpa
    "ptr:10.0.0.1.in-addr.arpa",
    # include:spf.fake.test
    "172.16.0.1",
    "172.16.0.0/24",
    "172.16.0.1/32",
    # ip6: ...
    "2001:4860:4000::",
    "2404:6800:4000::/36",
    # ip4: ...
    "10.0.0.1",
    "10.0.0.0/24",
    "10.0.0.1/32",
    # exists:fake.test
    "exists:fake.test",
]
