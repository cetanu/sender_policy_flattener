# coding=utf-8
import argparse
import json

from sender_policy_flattener.crawler import SPFCrawler
from sender_policy_flattener.formatting import sequence_hash
from sender_policy_flattener.email_utils import email_changes


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--config', dest='config',
        help='Name/path of JSON configuration file',
        default=None, required=False)

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


def flatten(input_records,
            dns_servers, email_server,
            email_subject, fromaddress, toaddress,
            lastresult=None):

    if lastresult is None:
        lastresult = dict()

    current = dict()
    crawler = SPFCrawler(dns_servers)
    for domain, spf_targets in input_records:
        records = crawler.spf2ips(spf_targets, domain)
        hashsum = sequence_hash(records)

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
                    curr_addrs=current[domain]['records'],
                    subject=email_subject,
                    server=email_server,
                    fromaddr=fromaddress,
                    toaddr=toaddress,
                )
    return current


if __name__ == "__main__":
    args = parse_arguments()

    if not args.config:
        settings = {}
    else:
        with open(args.config) as config:
            settings = json.load(config)

    nameservers = settings.get('resolvers', None) or args.resolvers
    mailserver = settings.get('email', {}).get('server', None)
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
            spf = flatten(
                input_records=spf_domains,
                lastresult=previous_result,
                dns_servers=nameservers,
                email_server=mailserver,
                fromaddress=fromaddr,
                toaddress=toaddr,
                email_subject=subject
            )
    except FileNotFoundError as e:
        spf = flatten(
            input_records=spf_domains,
            dns_servers=nameservers,
            email_server=mailserver,
            fromaddress=fromaddr,
            toaddress=toaddr,
            email_subject=subject
        )
    except Exception as e:
        print(repr(e))
    finally:
        with open(output, 'w+') as f:
            json.dump(spf, f, indent=4, sort_keys=True)
