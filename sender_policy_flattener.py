"""
    SPF Flattener script

    WHAT IT DOES
        1. DNS Lookups on your specified records, returns their ipv4 addresses
        2. Recursively finds 'includes' and other hostnames, returns their ipv4 addresses
        2. Dedupes network blocks
        3. Generates new records, each below 512 bytes
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from difflib import HtmlDiff

# noinspection PyUnresolvedReferences, PyPackageRequirements
# 3rd party imports
from dns import resolver  # dnspython/3
from netaddr import IPSet


def hash_seq(iterable):
    """ Acts as a centrifuge for our SPF records and returns a hash """
    flat_sorted_sequence = ' '.join(sorted([token for string in iterable for token in string.split()]))
    return hashlib.sha256(flat_sorted_sequence.encode()).hexdigest()


def bytelength(addresses):
    quote_allowance = '" "' * (len(addresses) // 4)
    return sys.getsizeof('v=spf1 {addresses} {quotes} include:spf1.example.domain.com -all'.format(
        addresses=' ip4:'.join(addresses),
        quotes=quote_allowance
    ))


def recurse_lookup(resourcerecord, resourcetype):
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
        match = dns_answer.search(result)
        answers = match.group('answers')
        if resourcetype == 'a':
            addresses = a_record.findall(answers)
        elif resourcetype == 'cname':
            name = answers.split()
            if len(name):
                name = str(name[-1]).rstrip('.')
                addresses = recurse_lookup(name, 'a')
            else:
                addresses = []
        else:
            addresses = ip_address.findall(answers)
        includes = spf_include.findall(answers)

        for ip in addresses:
            if resourcetype == 'a' and '/' not in ip:
                ip += '/32'
            yield ip

        if includes:
            for includetype, hostname in includes:
                includetype = includetype.lower().strip(' 1234567890')  # Remove priority info from mx records
                includetype = includetype.replace('include', 'txt')
                includetype = includetype.replace('ptr', 'cname')
                for ip in recurse_lookup(hostname, includetype):
                    yield ip


def separate_into_512bytes(ips):
    ipv4blocks = [ips]
    for index, addresses in enumerate(ipv4blocks):
        while bytelength(addresses) >= 512:  # 485 allows for spf prefix/suffixes, such as includes
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


def flatten(records, domain):
    ips = set()
    for rrecord, rdtype in records.items():
        for ip in recurse_lookup(rrecord, rdtype):
            ips.add(ip)
    ips = [str(s) for s in IPSet(ips).iter_cidrs()]
    ips = ['ip6:' + ip if ':' in ip else
           'ip4:' + ip.replace('/32', '')
           for ip in ips]
    ipv4blocks, last_record = separate_into_512bytes(ips)
    return [record for record in wrap_in_spf_tokens(domain, ipv4blocks, last_record)]


def output_bind_compatible(spfrec):
    spfrec = spfrec.split()
    ret = list()
    while spfrec:
        line, end = '"', '"'
        if not len(ret):
            line = '( "'
        try:
            for i in range(4):
                line += spfrec.pop(0) + ' '
        except IndexError:
            end = '" )'
        finally:
            ret.append(line + end)
    return ret


def email_changes(prev_addrs, curr_addrs):
    bindformat = list()
    for record in curr_addrs:
        for string in output_bind_compatible(record):
            bindformat.append(string)
    bindformat = '<p><h1>BIND compatible format:</h1><pre>' + '\n'.join(bindformat) + '</pre></p>'

    prev_addrs = ' '.join(prev_addrs)
    curr_addrs = ' '.join(curr_addrs)
    prev = sorted([s for s in prev_addrs.split() if not re.search(pattern=r'(include|spf|all)', string=s)])
    curr = sorted([s for s in curr_addrs.split() if not re.search(pattern=r'(include|spf|all)', string=s)])

    diff = HtmlDiff()
    table = diff.make_table(
        fromlines=prev,
        tolines=curr,
        fromdesc='Old records',
        todesc='New records'
    )

    header = '<h1>Diff</h1>'
    html = style + bindformat + header + table
    html = MIMEText(html, 'html')
    msg_template = MIMEMultipart('alternative')
    msg_template['Subject'] = subject.format(zone=zone)
    email = msg_template
    email.attach(html)

    try:
        mailserver = smtplib.SMTP()
        mailserver.connect(settings['email']['server'])
        mailserver.sendmail(fromaddr, toaddr, email.as_string())
    except Exception as e:
        print('Email failed: ' + str(e))
        with open('result.html', 'w+') as f:
            f.write(html.as_string())


if __name__ == "__main__":
    with open('settings.json') as y:
        settings = json.load(y)

    #
    # Nameserver setup
    #
    nameserver = resolver.Resolver()
    nameserver.nameservers = [resolver for resolver in settings['resolvers']]

    #
    # Various regexes
    #
    dns_answer = re.compile(r'ANSWER\n(?P<answers>[^;]+)')
    ip_address = re.compile(r'(?<=ip[46]:)\S+')
    a_record = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})')
    spf_include = re.compile(r'(?P<type>include|a|mx(?: \d+)? ?|ptr|cname ?)[:](?P<hostname>[^\s\'\"]+\w)',
                             flags=re.IGNORECASE)
    #
    # Email setup
    #
    fromaddr = settings['email']['from']
    toaddr = settings['email']['to']
    subject = settings['email']['subject']
    sending_domains = settings['sending domains'].items()
    style = '''
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

    #
    # Begin resolving and flattening
    #
    curr_spf = dict()
    try:
        with open(settings['output']) as prev_hashes:
            prev_spf = json.load(prev_hashes)
    except Exception as e:
        print(e)
        for zone, domains in sending_domains:
            spfrecords = flatten(domains, zone)
            shasum = hash_seq(spfrecords)
            curr_spf[zone] = {
                'sum': shasum,
                'records': spfrecords
            }
    else:
        for zone, domains in sending_domains:
            spfrecords = flatten(domains, zone)
            shasum = hash_seq(spfrecords)
            curr_spf[zone] = {
                'sum': shasum,
                'records': spfrecords
            }
            if prev_spf.get(zone, False) and curr_spf.get(zone, False):
                if prev_spf[zone]['sum'] != curr_spf[zone]['sum']:
                    previous = prev_spf[zone]['records']
                    current = curr_spf[zone]['records']
                    email_changes(previous, current)
    finally:
        with open(settings['output'], 'w+') as sumsfile:
            json.dump(curr_spf, sumsfile, indent=4, sort_keys=True)
