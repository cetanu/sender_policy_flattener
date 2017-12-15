# coding=utf-8
import sys

from dns import resolver  # dnspython/3
from netaddr import IPSet, IPNetwork

from sender_policy_flattener.formatting import wrap_in_spf_tokens
from sender_policy_flattener.mechanisms import tokenize


if 'FileNotFoundError' not in locals():
    FileNotFoundError = IOError


def sanitize(s):
    s = str(s)
    s = s.replace('"', '')
    return s


def ips_to_spf_strings(ips):
    ips = [sanitize(s) for s in ips]
    ips = [i for i in IPSet(ips).iter_cidrs()]
    ips = [sanitize(s) for s in ips]
    ips = ['ip6:' + ip if ':' in ip else
           'ip4:' + ip.replace('/32', '')
           for ip in ips]
    return ips


class SPFCrawler(object):
    def __init__(self, nameservers):
        self.ns = resolver.Resolver()
        if ',' in nameservers:
            nameservers = nameservers.split(',')
        if isinstance(nameservers, str):
            nameservers = [nameservers]
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
        ips = ips_to_spf_strings(ips)
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

    def _crawl(self, rrname, rrtype, domain):
        try:
            answers = self.ns.query(rrname, rrtype)
        except Exception as err:
            print(repr(err), rrname, rrtype)
        else:
            for answer in answers:
                for pair in tokenize(answer):
                    rname, rtype = pair
                    if rtype == 'ip':
                        yield rname
                        continue


    # def _crawl(self, rrecord, rrtype):
    #     try:
    #         # This query takes up 85% of execution time
    #         query = self.ns.query(rrecord, rrtype)
    #         result = query.response.to_text()
    #         result = result.replace('" "', '')
    #     except Exception as err:
    #         print(repr(err), rrecord, rrtype)
    #     else:
    #         match = dig_answer.search(result)
    #         answers = match.group('answers')
    #
    #         addresses = list()
    #         addresses += ipv4.findall(answers)
    #         addresses += ip.findall(answers)
    #
    #         if rrtype == 'cname':
    #             name = answers.split()
    #             if len(name):
    #                 name = str(name[-1]).rstrip('.')
    #                 addresses = self._crawl(name, 'a')
    #             else:
    #                 addresses = []
    #         if rrtype == 'mx':
    #             yield {
    #                 'query': query,
    #                 'response': query.response,
    #                 'list': [x for x in query]
    #             }
    #
    #         includes = spf_txt_or_include.findall(answers)
    #
    #         for ip in addresses:
    #             if rrtype == 'a' and '/' not in ip:
    #                 ip += '/32'
    #             yield ip
    #
    #         if includes:
    #             for includetype, hostname in includes:
    #                 includetype = includetype.lower().strip(' 1234567890')  # Remove priority info from mx records
    #                 includetype = includetype.replace('include', 'txt')
    #                 for ip in self._crawl(hostname, includetype):
    #                     yield ip
