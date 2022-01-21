# coding=utf-8
import json
from dns.resolver import Resolver
from sender_policy_flattener.crawler import spf2ips
from sender_policy_flattener.formatting import sequence_hash
from sender_policy_flattener.email_utils import email_changes

if "FileNotFoundError" not in locals():
    FileNotFoundError = IOError


def flatten(
    input_records,
    dns_servers,
    email_server,
    email_subject,
    fromaddress,
    toaddress,
    lastresult=None,
):
    resolver = Resolver()
    resolver.nameservers = dns_servers
    if lastresult is None:
        lastresult = dict()
    current = dict()
    for domain, spf_targets in input_records.items():
        records = spf2ips(spf_targets, domain, resolver)
        hashsum = sequence_hash(records)
        current[domain] = {"sum": hashsum, "records": records}
        if lastresult.get(domain, False) and current.get(domain, False):
            previous_sum = lastresult[domain]["sum"]
            current_sum = current[domain]["sum"]
            if previous_sum != current_sum:
                email_changes(
                    zone=domain,
                    prev_addrs=lastresult[domain]["records"],
                    curr_addrs=current[domain]["records"],
                    subject=email_subject,
                    server=email_server,
                    fromaddr=fromaddress,
                    toaddr=toaddress,
                )
    return current


def main(args):
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
            email_subject=args.subject,
        )
        with open(args.output, "w+") as f:
            json.dump(spf, f, indent=4, sort_keys=True)
