# coding=utf-8
import asyncio
import json
from pathlib import Path
from typing import TypedDict

import dns.asyncresolver
import structlog

from sender_policy_flattener.config import AppConfig, EmailConfig
from sender_policy_flattener.crawler import spf2ips
from sender_policy_flattener.formatting import sequence_hash, SourceMap
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.report import write_change_report

Domain = str
EmailAddress = str
IPAddress = str

log = structlog.get_logger(__name__)


class DomainState(TypedDict):
    sum: str
    records: list[str]
    # Raw IP/netblock -> include(s) it was resolved from.
    sources: SourceMap


async def flatten(
    input_records: dict[Domain, dict[Domain, str]],
    dns_servers: list[IPAddress],
    email_config: EmailConfig | None = None,
    # Loose on purpose: this comes from a previous run's on-disk JSON (or a
    # caller/test-supplied dict), which may predate the "sources" field.
    lastresult: dict[Domain, dict[str, object]] | None = None,
    static_ips: list[IPAddress] | None = None,
    report_dir: str | None = None,
) -> tuple[dict[Domain, DomainState], list[Domain]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = dns_servers
    if lastresult is None:
        lastresult = dict()

    async def _process(
        domain: Domain, spf_targets: dict[Domain, str]
    ) -> tuple[Domain, DomainState]:
        sources: dict[str, set[str]] = {}
        records = await spf2ips(
            spf_targets, domain, resolver, static_ips=static_ips, sources_out=sources
        )
        hashsum = sequence_hash(records)
        serializable_sources = {ip: sorted(srcs) for ip, srcs in sources.items()}
        return domain, {
            "sum": hashsum,
            "records": records,
            "sources": serializable_sources,
        }

    results = await asyncio.gather(
        *(_process(domain, targets) for domain, targets in input_records.items())
    )

    current: dict[Domain, DomainState] = dict(results)
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
                    raw_prev_sources = lastresult[domain].get("sources", {})
                    prev_sources: SourceMap = (
                        raw_prev_sources if isinstance(raw_prev_sources, dict) else {}
                    )
                    curr_sources = entry["sources"]
                    if email_config is not None:
                        email_changes(
                            zone=domain,
                            prev_addrs=prev_addrs,
                            curr_addrs=curr_addrs,
                            subject=email_config.subject,
                            config=email_config,
                            prev_sources=prev_sources,
                            curr_sources=curr_sources,
                        )
                    if report_dir is not None:
                        write_change_report(
                            report_dir,
                            domain,
                            prev_addrs,
                            curr_addrs,
                            prev_sources=prev_sources,
                            curr_sources=curr_sources,
                        )
    return current, changed_domains


async def run(config: AppConfig) -> list[Domain]:
    previous_result: dict[Domain, dict[str, object]] | None = None
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
