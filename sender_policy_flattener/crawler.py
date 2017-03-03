# coding=utf-8
import sys

from dns import resolver  # dnspython/3
from netaddr import IPSet

from sender_policy_flattener.formatting import wrap_in_spf_tokens
from sender_policy_flattener.regexes import ipv4, spf_ip, spf_txt_or_include, dig_answer


class SPFCrawler:
    def __init__(self, nameservers):
        self.ns = resolver.Resolver()
        self.ns.nameservers = nameservers

    @staticmethod
    def _rrecord_bytelength(addresses):
        quote_allowance = '" "' * (len(addresses) // 4)
        return sys.getsizeof('v=spf1 {addresses} {quotes} include:spf1.example.domain.com -all'.format(
            addresses=' ip4:'.join(addresses),
            quotes=quote_allowance
        ))

    def spf2ips(self, records, domain):
        ips = set()
        for rrecord, rdtype in records.items():
            for ip in self._crawl(rrecord, rdtype):
                ips.add(ip)
        ips = [str(s) for s in IPSet(ips).iter_cidrs()]
        ips = ['ip6:' + ip if ':' in ip else
               'ip4:' + ip.replace('/32', '')
               for ip in ips]
        ipv4blocks, last_record = self._split_at_450bytes(ips)
        return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]

    def _split_at_450bytes(self, ips):
        ipv4blocks = [set(ips)]
        for index, addresses in enumerate(ipv4blocks):
            while self._rrecord_bytelength(addresses) >= 450:  # https://tools.ietf.org/html/rfc4408
                overflow = ipv4blocks[index].pop()
                try:
                    ipv4blocks[index + 1]
                except IndexError:
                    ipv4blocks.append(set())
                finally:
                    ipv4blocks[index + 1].add(overflow)
        last_record = len(ipv4blocks) - 1
        return ipv4blocks, last_record

    def _crawl(self, rrecord, rrtype):
        try:
            # This query takes up 85% of execution time
            result = self.ns.query(rrecord, rrtype).response.to_text()
            result = result.replace('" "', '')
        except Exception as err:
            print(repr(err), rrecord, rrtype)
        else:
            match = dig_answer.search(result)
            answers = match.group('answers')
            if rrtype == 'a':
                addresses = ipv4.findall(answers)
            elif rrtype == 'cname':
                name = answers.split()
                if len(name):
                    name = str(name[-1]).rstrip('.')
                    addresses = self._crawl(name, 'a')
                else:
                    addresses = []
            else:
                addresses = spf_ip.findall(answers)

            includes = spf_txt_or_include.findall(answers)

            for ip in addresses:
                if rrtype == 'a' and '/' not in ip:
                    ip += '/32'
                yield ip

            if includes:
                for includetype, hostname in includes:
                    includetype = includetype.lower().strip(' 1234567890')  # Remove priority info from mx records
                    includetype = includetype.replace('include', 'txt')
                    includetype = includetype.replace('ptr', 'cname')
                    for ip in self._crawl(hostname, includetype):
                        yield ip
