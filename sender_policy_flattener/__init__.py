# coding=utf-8
import asyncio
import json
from pathlib import Path

import dns.asyncresolver
import structlog

from sender_policy_flattener.config import AppConfig, EmailConfig
from sender_policy_flattener.crawler import spf2ips
from sender_policy_flattener.formatting import sequence_hash
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.report import write_change_report

Domain = str
EmailAddress = str
IPAddress = str

log = structlog.get_logger(__name__)


async def flatten(
    input_records: dict[Domain, dict[Domain, str]],
    dns_servers: list[IPAddress],
    email_config: EmailConfig | None = None,
    lastresult: dict[Domain, dict[str, str | list[str]]] | None = None,
    static_ips: list[IPAddress] | None = None,
    report_dir: str | None = None,
) -> tuple[dict[Domain, dict[str, str | list[str]]], list[Domain]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = dns_servers
    if lastresult is None:
        lastresult = dict()

    async def _process(
        domain: Domain, spf_targets: dict[Domain, str]
    ) -> tuple[Domain, dict[str, str | list[str]]]:
        records = await spf2ips(spf_targets, domain, resolver, static_ips=static_ips)
        hashsum = sequence_hash(records)
        return domain, {"sum": hashsum, "records": records}

    results = await asyncio.gather(
        *(_process(domain, targets) for domain, targets in input_records.items())
    )

    current: dict[Domain, dict[str, str | list[str]]] = dict(results)
    changed_domains: list[Domain] = []
    for domain, entry in current.items():
        if lastresult.get(domain, False) and entry:
            previous_sum = lastresult[domain]["sum"]
            current_sum = entry["sum"]
            if previous_sum != current_sum:
                prev_addrs = lastresult[domain]["records"]
                curr_addrs = entry["records"]
                if isinstance(prev_addrs, list) and isinstance(curr_addrs, list):
                    changed_domains.append(domain)
                    if email_config is not None:
                        email_changes(
                            zone=domain,
                            prev_addrs=prev_addrs,
                            curr_addrs=curr_addrs,
                            subject=email_config.subject,
                            config=email_config,
                        )
                    if report_dir is not None:
                        write_change_report(report_dir, domain, prev_addrs, curr_addrs)
    return current, changed_domains


async def run(config: AppConfig) -> list[Domain]:
    previous_result: dict[Domain, dict[str, str | list[str]]] | None = None
    output_path = Path(config.output)
    changed_domains: list[Domain] = []
    try:
        with output_path.open() as prev_hashes:
            previous_result = json.load(prev_hashes)
    except FileNotFoundError as e:
        log.info("no_previous_result", error=str(e))
    except Exception as e:
        log.warning("failed_to_load_previous_result", error=repr(e))
    finally:
        spf, changed_domains = await flatten(
            input_records=config.sending_domains,
            lastresult=previous_result,
            dns_servers=config.resolvers,
            email_config=config.email,
            static_ips=config.static_ips,
            report_dir=config.report_dir,
        )
        with output_path.open("w+") as f:
            json.dump(spf, f, indent=4, sort_keys=True)
    return changed_domains
