"""
    SPF Flattener script

    WHAT IT DOES
        1. DNS Lookups on your specified records, returns their ipv4 addresses
        2. Recursively finds 'includes' and other hostnames, returns their ipv4 addresses
        2. Dedupes network blocks
        3. Generates new records, each below 450 bytes
        4. Saves the result, plus a hash of the result, in a file
        5. Will compare with the previous records on the next run, and email if they are different

    INSTRUCTIONS
        Fill out the JSON file with your domains, with record:type values.
        Also add some resolvers. Try resolvers that the public might use.
"""
# builtins
import re
import sys
import json
import hashlib
import smtplib
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from difflib import HtmlDiff

# noinspection PyUnresolvedReferences, PyPackageRequirements
# 3rd party imports
from dns import resolver  # dnspython/3
from netaddr import IPSet

# pre-compile regular expressions
re_dig_answer = re.compile(r'ANSWER\n(?P<answers>[^;]+)')
re_ipv4 = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})')
re_spf_ip = re.compile(r'(?<=ip[46]:)\S+')
re_spf_txt_or_include = re.compile(r'(?P<type>include|a|mx(?: \d+)? ?|ptr|cname ?)[:](?P<hostname>[^\s\'\"]+\w)', flags=re.IGNORECASE)
re_spf_token = re.compile(r'(include|spf|all)')

_email_style = '''
    <style type="text/css">
        body {font-family: "Helvetica Neue Light", "Lucida Grande", "Calibri", "Arial", sans-serif;}
        a {text-decoration: none; color: royalblue; padding: 5px;}
        a:visited {color: royalblue}
        a:hover {background-color: royalblue; color: white;}
        h1 {
            font-family: "Helvetica Neue Light", "Lucida Grande", "Calibri", "Arial", sans-serif;
            font-size: 14pt;
        }
        table.diff {border: 1px solid black;}
        td {padding: 5px;}
        td.diff_header {text-align:right}
        .diff_header {background-color:#e0e0e0}
        .diff_next {background-color:#c0c0c0}
        .diff_add {background-color:#aaffaa}
        .diff_chg {background-color:#ffff77}
        .diff_sub {background-color:#ffaaaa}
    </style>
    '''


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--config', dest='config',
        help='Name/path of JSON configuration file',
        default='settings.json', required=False)

    parser.add_argument(
        '-r', '--resolvers', dest='resolvers',
        help='Comma separated DNS servers to be used',
        default='8.8.8.8,8.8.4.4', required=False)

    parser.add_argument(
        '-t', '-to', dest='toaddr',
        help='Recipient address for email alert',
        default=None, required=False)

    parser.add_argument(
        '-f', '-from', dest='fromaddr',
        help='Sending address for email alert',
        default=None, required=False)

    parser.add_argument(
        '-s', '-subject', dest='subject',
        help='Subject string, must contain {zone}',
        default=None, required=False)

    parser.add_argument(
        '-d', '--domains', dest='domains',
        help='Comma separated domain:rrtype to flatten to IP addresses',
        default=None, required=False)

    parser.add_argument(
        '-o', '--output', dest='output',
        help='Name/path of output file',
        default='spf_sums.json', required=False)

    return parser.parse_args()


def hashed_sequence(iterable):
    """ Acts as a centrifuge for our SPF records and returns a hash """
    flat_sorted_sequence = ' '.join(sorted([token for string in iterable for token in string.split()]))
    return hashlib.sha256(flat_sorted_sequence.encode()).hexdigest()


def recordbytelength(addresses):
    quote_allowance = '" "' * (len(addresses) // 4)
    return sys.getsizeof('v=spf1 {addresses} {quotes} include:spf1.example.domain.com -all'.format(
        addresses=' ip4:'.join(addresses),
        quotes=quote_allowance
    ))


def crawl_spf_record(resourcerecord, resourcetype):
    """
        Finds IPv4 Addresses, plus hostnames.

        If there are hostnames, it calls itself to extract the IPv4 addresses from them
        It then returns a collection of all of the found addresses.
    """
    try:
        # This query takes up 85% of execution time
        result = nameserver.query(resourcerecord, resourcetype).response.to_text()
        result = result.replace('" "', '')
    except Exception as err:
        print(repr(err), resourcerecord, resourcetype)
    else:
        match = re_dig_answer.search(result)
        answers = match.group('answers')
        if resourcetype == 'a':
            addresses = re_ipv4.findall(answers)
        elif resourcetype == 'cname':
            name = answers.split()
            if len(name):
                name = str(name[-1]).rstrip('.')
                addresses = crawl_spf_record(name, 'a')
            else:
                addresses = []
        else:
            addresses = re_spf_ip.findall(answers)

        includes = re_spf_txt_or_include.findall(answers)

        for ip in addresses:
            if resourcetype == 'a' and '/' not in ip:
                ip += '/32'
            yield ip

        if includes:
            for includetype, hostname in includes:
                includetype = includetype.lower().strip(' 1234567890')  # Remove priority info from mx records
                includetype = includetype.replace('include', 'txt')
                includetype = includetype.replace('ptr', 'cname')
                for ip in crawl_spf_record(hostname, includetype):
                    yield ip


def separate_into_450bytes(ips):
    ipv4blocks = [ips]
    for index, addresses in enumerate(ipv4blocks):
        while recordbytelength(addresses) >= 450:  # https://tools.ietf.org/html/rfc4408
            overflow = ipv4blocks[index].pop()
            try:
                ipv4blocks[index + 1]
            except IndexError:
                ipv4blocks.append(set())
            finally:
                ipv4blocks[index + 1].add(overflow)
    last_record = len(ipv4blocks) - 1
    return ipv4blocks, last_record


def wrap_in_spf_tokens(domain, ipv4blocks, last_record):
    for spf_num, spf_set in enumerate(ipv4blocks):
        spf_set = ' '.join(spf_set)
        if spf_num == last_record:
            spfrecord = 'v=spf1 {0} -all'.format(spf_set)
        else:
            spfrecord = 'v=spf1 {0} include:spf{1}.{2} -all'.format(spf_set, spf_num + 1, domain)
        yield spfrecord


def spf2ips(records, domain):
    ips = set()
    for rrecord, rdtype in records.items():
        for ip in crawl_spf_record(rrecord, rdtype):
            ips.add(ip)
    ips = [str(s) for s in IPSet(ips).iter_cidrs()]
    ips = ['ip6:' + ip if ':' in ip else
           'ip4:' + ip.replace('/32', '')
           for ip in ips]
    ipv4blocks, last_record = separate_into_450bytes(ips)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]


def bind_compatible_string(spfrec):
    spfrec = spfrec.split()
    while spfrec:
        line, end = '"', '"'
        if not len((line + end).strip('"')):
            line = '( "'
        try:
            for i in range(4):
                line += spfrec.pop(0) + ' '
        except IndexError:
            end = '" )'
        finally:
            yield line + end


def email_changes(zone, prev_addrs, curr_addrs):
    bindformat = list()
    for record in curr_addrs:
        bindformat += list(bind_compatible_string(record))
    bindformat = '<p><h1>BIND compatible format:</h1><pre>' + '\n'.join(bindformat) + '</pre></p>'

    prev_addrs = ' '.join(prev_addrs)
    curr_addrs = ' '.join(curr_addrs)
    prev = sorted([s for s in prev_addrs.split() if not re_spf_token.search(s)])
    curr = sorted([s for s in curr_addrs.split() if not re_spf_token.search(s)])

    diff = HtmlDiff()
    table = diff.make_table(
        fromlines=prev,
        tolines=curr,
        fromdesc='Old records',
        todesc='New records'
    )

    header = '<h1>Diff</h1>'
    html = _email_style + bindformat + header + table
    html = MIMEText(html, 'html')
    msg_template = MIMEMultipart('alternative')
    msg_template['Subject'] = subject.format(zone=zone)
    email = msg_template
    email.attach(html)

    try:
        mailserver = smtplib.SMTP()
        mailserver.connect(settings['email']['server'])
        mailserver.sendmail(fromaddr, toaddr, email.as_string())
    except Exception as err:
        print('Email failed: ' + str(err))
        with open('result.html', 'w+') as mailfile:
            mailfile.write(html.as_string())


def flatten(input_records, lastresult=None):
    current = dict()
    for domain, spf_targets in input_records:
        records = spf2ips(spf_targets, domain)
        hashsum = hashed_sequence(records)
        current[domain] = {
            'sum': hashsum,
            'records': records
        }

        if lastresult.get(domain, False) and current.get(domain, False):
            previous_sum = lastresult[domain]['sum']
            current_sum = current[domain]['sum']

            if previous_sum != current_sum:
                email_changes(
                    zone=domain,
                    prev_addrs=lastresult[domain]['records'],
                    curr_addrs=current[domain]['records']
                )
    return current


if __name__ == "__main__":
    args = parse_arguments()

    if not args.config:
        settings = {}
    else:
        with open(args.config) as config:
            settings = json.load(config)

    nameserver = resolver.Resolver()
    nameserver.nameservers = settings.get('resolvers', None) or args.resolvers

    fromaddr = settings.get('email', {}).get('from', None) or args.fromaddr
    toaddr = settings.get('email', {}).get('to', None) or args.toaddr
    subject = settings.get('email', {}).get('subject', None) or args.subject

    spf_domains = args.domains if args.domains else settings['sending domains'].items()
    output = settings.get('output', None) or args.output

    if '{zone}' not in subject:
        raise ValueError('Subject must contain {zone}')

    spf = dict()
    try:
        with open(output) as prev_hashes:
            previous_result = json.load(prev_hashes)
            spf = flatten(spf_domains, previous_result)
    except FileNotFoundError as e:
        spf = flatten(spf_domains)
    except Exception as e:
        print(repr(e))
    finally:
        with open(output, 'w+') as f:
            json.dump(spf, f, indent=4, sort_keys=True)
