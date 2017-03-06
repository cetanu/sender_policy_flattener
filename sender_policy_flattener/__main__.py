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
        '-e', '-mailserver', dest='mailserver',
        help='Server to use for mailing alerts',
        default=None, required=False)

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

    arguments = parser.parse_args()

    if arguments.config:
        with open(arguments.config) as config:
            settings = json.load(config)
            arguments.resolvers = settings['resolvers']
            arguments.toaddr = settings['email']['to']
            arguments.fromaddr = settings['email']['from']
            arguments.subject = settings['email']['subject']
            arguments.mailserver = settings['email']['server']
            arguments.domains = settings['sending domains']
            arguments.output = settings['output']

    required_non_config_args = all([
        arguments.toaddr,
        arguments.fromaddr,
        arguments.subject,
        arguments.mailserver,
        arguments.domains,
    ])

    if not required_non_config_args:
        parser.print_usage()
        exit()

    if '{zone}' not in arguments.subject:
        raise ValueError('Subject must contain {zone}')

    return arguments


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
    spf = dict()
    previous_result = None
    try:
        with open(args.output) as prev_hashes:
            previous_result = json.load(prev_hashes)
    except FileNotFoundError as e:
        print(repr(e))
    except Exception as e:
        print(repr(e))
    finally:
        spf = flatten(
            input_records=args.domains,
            lastresult=previous_result,
            dns_servers=args.resolvers,
            email_server=args.mailserver,
            fromaddress=args.fromaddr,
            toaddress=args.toaddr,
            email_subject=args.subject
        )
        with open(args.output, 'w+') as f:
            json.dump(spf, f, indent=4, sort_keys=True)
