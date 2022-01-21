# coding=utf-8

expected_final_email = """
<p><h1>BIND compatible format:</h1><pre>@ IN TXT (
"v=spf1 exists:fake.test ip4:10.0.0.0/24 ip4:172.16.0.0/24 "
"ip4:192.168.0.1/26 ip6:2001:4860:4000::/128 ip6:2404:6800:4000::/36 ptr:10.0.0.1.in-addr.arpa "
"-all "
 )</pre></p>
 """.strip()
