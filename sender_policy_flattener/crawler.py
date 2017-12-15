# coding=utf-8

from dns import resolver  # dnspython/3
from sender_policy_flattener.formatting import wrap_in_spf_tokens, ips_to_spf_strings, fit_bytes
from sender_policy_flattener.mechanisms import tokenize


default_resolvers = resolver.Resolver()


def spf2ips(records, domain, resolvers=default_resolvers):
    ips = set()
    for rrecord, rdtype in records.items():
        for ip in crawl(rrecord, rdtype, domain, resolvers):
            ips.add(ip)
    ips = ips_to_spf_strings(ips)
    ipv4blocks, last_record = fit_bytes(ips)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]


def crawl(rrname, rrtype, domain, ns=default_resolvers):
    try:
        answers = ns.query(rrname, rrtype)
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
