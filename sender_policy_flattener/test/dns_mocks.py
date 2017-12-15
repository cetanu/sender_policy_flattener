# coding=utf-8

test_com = """
id 50699
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
test.com. IN TXT
;ANSWER
test.com. 25 IN TXT "v=spf1 include:spf-a.outlook.com ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 exists:somedomain.com include:spf-b.outlook.com ip4:157.55.9.128/25 include:spf.protection.outlook.com include:spf-a.hotmail.com include:_spf-ssg-b.microsoft.com include:_spf-ssg-c.microsoft.com ~all"
test.com. 25 IN TXT "google-site-verification=DC2uC-T8kD33lINhNzfo0bNBrw-vrCXs5BPF5BXY56g
test.com. 25 IN TXT "google-site-verification=0iLWhIMhXEkeWwWfFU4ursTn-_OvoOjaA0Lr7Pg1sEM;AUTHORITY
;ADDITIONAL
""".strip()

spf_a_outlook = 'id 16665\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspf-a.outlook.com. IN TXT\n;ANSWER\nspf-a.outlook.com. 248 IN TXT "v=spf1 ip4:157.56.232.0/21 ip4:157.56.240.0/20 ip4:207.46.198.0/25 ip4:207.46.4.128/25 ip4:157.56.24.0/25 ip4:157.55.157.128/25 ip4:157.55.61.0/24 ip4:157.55.49.0/25 ip4:65.55.174.0/25 ip4:65.55.126.0/25 ip4:65.55.113.64/26 ip4:65.55.94.0/25 -all"\n;AUTHORITY\n;ADDITIONAL'
spf_b_outlook = 'id 46237\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspf-b.outlook.com. IN TXT\n;ANSWER\nspf-b.outlook.com. 300 IN TXT "v=spf1 ip4:65.55.78.128/25 ip4:111.221.112.0/21 ip4:207.46.58.128/25 ip4:111.221.69.128/25 ip4:111.221.66.0/25 ip4:111.221.23.128/25 ip4:70.37.151.128/25 ip4:157.56.248.0/21 ip4:213.199.177.0/26 ip4:157.55.225.0/25 ip4:157.55.11.0/25 -all"\n;AUTHORITY\n;ADDITIONAL'
spf_protection = 'id 29583\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspf.protection.outlook.com. IN TXT\n;ANSWER\nspf.protection.outlook.com. 599 IN TXT "v=spf1 ip4:207.46.101.128/26 ip4:207.46.100.0/24 ip4:207.46.163.0/24 ip4:65.55.169.0/24 ip4:157.56.110.0/23 ip4:157.55.234.0/24 ip4:213.199.154.0/24 ip4:213.199.180.128/26 include:spfa.protection.outlook.com -all"\n;AUTHORITY\n;ADDITIONAL'
spfa_protection = 'id 57802\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspfa.protection.outlook.com. IN TXT\n;ANSWER\nspfa.protection.outlook.com. 600 IN TXT "v=spf1 ip4:157.56.112.0/24 ip4:207.46.51.64/26 ip4:157.55.158.0/23 ip4:64.4.22.64/26 ip4:40.92.0.0/14 ip4:40.107.0.0/17 ip4:40.107.128.0/17 ip4:134.170.140.0/24 include:spfb.protection.outlook.com ip6:2001:489a:2202::/48 -all"\n;AUTHORITY\n;ADDITIONAL'
spfb_protection = 'id 54252\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspfb.protection.outlook.com. IN TXT\n;ANSWER\nspfb.protection.outlook.com. 599 IN TXT "v=spf1 ip6:2a01:111:f400::/48 ip4:23.103.128.0/19 ip4:23.103.198.0/23 ip4:65.55.88.0/24 ip4:104.47.0.0/17 ip4:23.103.200.0/21 ip4:23.103.208.0/21 ip4:23.103.191.0/24 ip4:216.32.180.0/23 ip4:94.245.120.64/26 -all"\n;AUTHORITY\n;ADDITIONAL'
spf_a_hotmail = 'id 65533\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nspf-a.hotmail.com. IN TXT\n;ANSWER\nspf-a.hotmail.com. 3600 IN TXT "v=spf1 ip4:157.55.0.192/26 ip4:157.55.1.128/26 ip4:157.55.2.0/25 ip4:65.54.190.0/24 ip4:65.54.51.64/26 ip4:65.54.61.64/26 ip4:65.55.111.0/24 ip4:65.55.116.0/25 ip4:65.55.34.0/24 ip4:65.55.90.0/24 ip4:65.54.241.0/24 ip4:207.46.117.0/24 ~all"\n;AUTHORITY\n;ADDITIONAL'
spf_ssg_b_microsoft = 'id 44438\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\n_spf-ssg-b.microsoft.com. IN TXT\n;ANSWER\n_spf-ssg-b.microsoft.com. 3600 IN TXT "v=spf1 ip4:207.68.169.173/30 ip4:207.68.176.0/26 ip4:207.46.132.128/27 ip4:207.68.176.96/27 ip4:65.55.238.129/26 ip4:65.55.238.129/26 ip4:207.46.116.128/29 ip4:65.55.178.128/27 ip4:213.199.161.128/27 ip4:65.55.33.64/28 ~all"\n;AUTHORITY\n;ADDITIONAL'
spf_ssg_c_microsoft = 'id 13128\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\n_spf-ssg-c.microsoft.com. IN TXT\n;ANSWER\n_spf-ssg-c.microsoft.com. 3600 IN TXT "v=spf1 ip4:65.54.121.120/29 ip4:65.55.81.48/28 ip4:65.55.234.192/26 ip4:207.46.200.0/27 ip4:65.55.52.224/27 ip4:94.245.112.10/31 ip4:94.245.112.0/27 ip4:111.221.26.0/27 ip4:207.46.50.192/26 ip4:207.46.50.224 ~all"\n;AUTHORITY\n;ADDITIONAL'

dns_responses = {
    'test.com': test_com,
    'spf-a.outlook.com': spf_a_outlook,
    'spf-b.outlook.com': spf_b_outlook,
    'spf.protection.outlook.com': spf_protection,
    'spfa.protection.outlook.com': spfa_protection,
    'spfb.protection.outlook.com': spfb_protection,
    'spf-a.hotmail.com': spf_a_hotmail,
    '_spf-ssg-b.microsoft.com': spf_ssg_b_microsoft,
    '_spf-ssg-c.microsoft.com': spf_ssg_c_microsoft,
}
