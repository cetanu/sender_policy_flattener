# coding=utf-8
import json
from argparse import Namespace

from dns.resolver import Resolver

from sender_policy_flattener.crawler import spf2ips
from sender_policy_flattener.formatting import sequence_hash
from sender_policy_flattener.email_utils import email_changes

Domain = str
EmailAddress = str
IPAddress = str

if "FileNotFoundError" not in locals():
    FileNotFoundError = IOError


def flatten(
    input_records: dict[Domain, dict[Domain, str]],
    dns_servers: list[IPAddress],
    email_server: str,
    email_subject: str,
    fromaddress: EmailAddress,
    toaddress: EmailAddress,
    lastresult: dict[Domain, dict[str, str | list[str]]] | None = None,
) -> dict[Domain, dict[str, str |list[str]]]:
    resolver = Resolver()
    resolver.nameservers = dns_servers
    if lastresult is None:
        lastresult = dict()
    current: dict[Domain, dict[str, str | list[str]]] = dict()
    for domain, spf_targets in input_records.items():
        records = spf2ips(spf_targets, domain, resolver)
        hashsum = sequence_hash(records)
        current[domain] = {"sum": hashsum, "records": records}
        if lastresult.get(domain, False) and current.get(domain, False):
            previous_sum = lastresult[domain]["sum"]
            current_sum = current[domain]["sum"]
            if previous_sum != current_sum:
                prev_addrs = lastresult[domain]["records"]
                curr_addrs = current[domain]["records"]
                if isinstance(prev_addrs, list) and isinstance(curr_addrs, list):
                    _bind_format = email_changes(
                        zone=domain,
                        prev_addrs=prev_addrs,
                        curr_addrs=curr_addrs,
                        subject=email_subject,
                        server=email_server,
                        fromaddr=fromaddress,
                        toaddr=toaddress,
                    )
    return current


def main(args: Namespace) -> None:
    previous_result: dict[Domain, dict[str, str | list[str]]]| None = None
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
