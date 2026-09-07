"""Shared DNS resolution helper with retry/backoff for transient failures."""

import dns.asyncresolver
import dns.exception
import dns.resolver
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

RRType = str


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, max=5),
    retry=retry_if_exception_type(dns.exception.Timeout),
)
async def resolve(
    ns: dns.asyncresolver.Resolver, name: str, rrtype: RRType
) -> dns.resolver.Answer:
    return await ns.resolve(name, rrtype)
