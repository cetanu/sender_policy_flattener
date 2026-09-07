# coding=utf-8
import json
from unittest import mock

import dns.asyncresolver
from typer.testing import CliRunner

from sender_policy_flattener import flatten
from sender_policy_flattener.cli import app as cli_app
from sender_policy_flattener.config import EmailConfig
from sender_policy_flattener.crawler import crawl, spf2ips, default_resolvers
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import (
    handle_ip,
    handle_mx,
    handle_mx_prefix,
    handle_mx_domain,
    handle_mx_domain_prefix,
    handle_a,
    handle_a_domain,
    handle_a_prefix,
    handle_a_domain_prefix,
)

cli_runner = CliRunner()


mocked_dns_object = "sender_policy_flattener.dns_utils.resolve"
expected_hash = "764567b38af1d413b346fd08df026e07bbcab6e70f73b039144900cc55fee1eb"
expected_large_hash = "103c78c52ee89aab2f55a32337d942191589c41613ab312279d050b63e774334"

test_email_config = EmailConfig(
    to="recipient@mocked.com",
    **{"from": "sender@mocked.com"},
    subject="{zone} has changed",
    server="mocked",
)


def MockDNSQuery(dns_responses, *args, **kwargs):
    _ns, rrecord, rrtype = args
    rrecord = str(rrecord)
    # normalize MX records "10 <domain>" to "<domain>"
    rrecord = rrecord.split()[-1]
    # remove TLD dot from all domains
    if rrecord.endswith("."):
        rrecord = rrecord.rstrip(".")
    _type = dns_responses[rrtype]
    _record = _type[rrecord]
    return _record


class MockSmtplib:
    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def starttls(self, *args, **kwargs):
            return None

        def login(self, *args, **kwargs):
            return None

        def connect(self, *args, **kwargs):
            return True

        def sendmail(self, *args, **kwargs):
            return True

    SMTP_PORT = 25


@mock.patch(mocked_dns_object)
async def test_ip(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) async for s in handle_ip("172.16.0.1", "test.com", default_resolvers)]
    expected = ["172.16.0.1"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_mx(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) async for s in handle_mx(("mx", "mx"), "test.com", default_resolvers)]
    expected = ["192.168.0.10"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_mx_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_mx_prefix(["mx", "29"], "test.com", default_resolvers)
    ]
    expected = ["192.168.0.10/29"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_mx_domain(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_mx_domain("test.fake", "test.com", default_resolvers)
    ]
    expected = ["10.0.0.12", "10.0.0.13"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_mx_domain_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_mx_domain_prefix(
            ["test.fake", "27"], "test.com", default_resolvers
        )
    ]
    expected = ["10.0.0.12/27", "10.0.0.13/27"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_a(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) async for s in handle_a(("a", "a"), "test.com", default_resolvers)]
    expected = ["192.168.0.1"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_a_domain(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_a_domain("test.fake", "test.com", default_resolvers)
    ]
    expected = ["10.0.0.10", "10.0.0.11"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_a_domain_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_a_domain_prefix(
            ["test.fake", "24"], "test.com", default_resolvers
        )
    ]
    expected = ["10.0.0.10/24", "10.0.0.11/24"]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_a_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        async for s in handle_a_prefix(["a", "26"], "test.com", default_resolvers)
    ]
    expected = ["192.168.0.1/26"]
    assert expected == actual


def test_mechanism_a():
    actual = list(tokenize("v=spf1 a:test.com a a/28 a:test.com/27"))
    expected = [
        ("test.com", "a_domain"),
        ("a", "a"),
        (["a", "28"], "a_prefix"),
        (["test.com", "27"], "a_domain_prefix"),
    ]
    assert expected == actual


def test_mechanism_mx():
    actual = list(tokenize("v=spf1 mx:test.com mx mx/28 mx:test.com/27"))
    expected = [
        ("test.com", "mx_domain"),
        ("mx", "mx"),
        (["mx", "28"], "mx_prefix"),
        (["test.com", "27"], "mx_domain_prefix"),
    ]
    assert expected, actual


def test_mechanism_ptr():
    actual = list(tokenize("v=spf1 ptr ptr:1.1.1.1.in-addr.arpa"))
    expected = [
        ("ptr", "ptr"),
        ("1.1.1.1.in-addr.arpa", "ptr"),
    ]
    assert expected == actual


def test_mechanism_include():
    actual = list(tokenize("v=spf1 include:spf.test.com"))
    expected = [
        ("spf.test.com", "txt"),
    ]
    assert expected == actual


def test_mechanism_exists():
    actual = list(tokenize("v=spf1 exists:validate.test.com"))
    expected = [
        ("validate.test.com", "exists"),
    ]
    assert expected == actual


def test_mechanism_ip():
    actual = list(
        tokenize(
            "v=spf1 ip4:123.123.123.123 ip4:123.123.123.123/24 ip6:2001:4860:4000:: ip6:2001:4860:4000::/36"
        )
    )
    expected = [
        ("123.123.123.123", "ip"),
        ("123.123.123.123/24", "ip"),
        ("2001:4860:4000::", "ip"),
        ("2001:4860:4000::/36", "ip"),
    ]
    assert expected == actual


@mock.patch(mocked_dns_object)
async def test_crawler_returns_all_expected_ips(
    mock_query, dns_responses, test_com_netblocks
):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) async for s in crawl("test.com", "txt", "test.com")]
    assert test_com_netblocks == actual


@mock.patch(mocked_dns_object)
async def test_crawler_top_level_a_rrtype_resolves_named_domain(mock_query, dns_responses):
    # Regression test: a top-level "sending domains" entry like
    # {"example.com": "a"} must resolve example.com's own A record,
    # not silently yield nothing (see issue #17).
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) async for s in crawl("test.fake", "a", "test.com")]
    assert actual == ["10.0.0.10", "10.0.0.11"]


@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", MockSmtplib)
async def test_call_main_flatten_func(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual, changed = await flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=test_email_config,
    )

    resolvers = dns.asyncresolver.Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = await spf2ips({"test.com": "txt"}, "test.com", resolvers=resolvers)
    expected_sources = {
        "10.0.0.0/24": ["test.com"],
        "10.0.0.1": ["test.com"],
        "10.0.0.1/32": ["test.com"],
        "10.0.0.10": ["test.com"],
        "10.0.0.11": ["test.com"],
        "10.0.0.12": ["test.com"],
        "10.0.0.12/27": ["test.com"],
        "10.0.0.13": ["test.com"],
        "10.0.0.13/27": ["test.com"],
        "172.16.0.0/24": ["spf.fake.test"],
        "172.16.0.1": ["spf.fake.test"],
        "172.16.0.1/32": ["spf.fake.test"],
        "192.168.0.1/26": ["test.com"],
        "2001:4860:4000::": ["test.com"],
        "2404:6800:4000::/36": ["test.com"],
        "exists:fake.test": ["test.com"],
        "ptr:10.0.0.1.in-addr.arpa": ["test.com"],
    }
    expected = {
        "test.com": {
            "records": expected_records,
            "sum": expected_hash,
            "sources": expected_sources,
        }
    }
    assert expected == actual
    assert changed == []


@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", MockSmtplib)
async def test_call_main_flatten_func_on_large_spf_records(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual, changed = await flatten(
        input_records={"test.com": {"galactus.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=test_email_config,
    )

    resolvers = dns.asyncresolver.Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = await spf2ips(
        {"galactus.com": "txt"}, "test.com", resolvers=resolvers
    )
    sources = actual["test.com"].pop("sources")
    expected = {"test.com": {"records": expected_records, "sum": expected_large_hash}}
    assert expected == actual
    assert changed == []
    # galactus.com is the only top-level target, so every raw netblock is
    # attributed to it regardless of how CIDR compaction later groups them.
    assert sources and all(v == ["galactus.com"] for v in sources.values())


@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", MockSmtplib)
async def test_bind_format(mock_query, dns_responses, expected_final_email):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)

    resolvers = dns.asyncresolver.Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = await spf2ips({"test.com": "txt"}, "test.com", resolvers=resolvers)
    actual = email_changes(
        zone="test.com",
        prev_addrs=[],
        curr_addrs=expected_records,
        subject="{zone} has changed",
        config=test_email_config,
        test=True,
    )
    assert actual
    assert actual.count("(") == actual.count("IN TXT")
    assert actual.count(")") == actual.count("IN TXT")
    assert expected_final_email == actual


@mock.patch(mocked_dns_object)
async def test_flatten_with_static_ips(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    static_ips = ["1.1.1.1", "2.2.2.0/24", "10.0.0.50/32"]
    actual, _changed = await flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=test_email_config,
        static_ips=static_ips,
    )
    expected = {
        "test.com": {
            "records": [
                "".join(
                    (
                        "v=spf1 exists:fake.test ip4:1.1.1.1 ip4:10.0.0.0/24 ",
                        "ip4:172.16.0.0/24 ip4:192.168.0.1/26 ip4:2.2.2.0/24 ",
                        "ip6:2001:4860:4000::/128 ip6:2404:6800:4000::/36 ",
                        "ptr:10.0.0.1.in-addr.arpa -all",
                    )
                )
            ],
            "sum": "bf89b41176a3ecc5ab21b036270d680d9431130d83afe5305be42f566f7e4131",
        }
    }
    sources = actual["test.com"].pop("sources")
    assert expected == actual

    # static ips and ranges are added
    assert static_ips[0] in actual["test.com"]["records"][0]
    assert static_ips[1] in actual["test.com"]["records"][0]

    # ip is compacted into 10.0.0.0/24
    assert static_ips[2] not in actual["test.com"]["records"][0]

    # raw static entries are attributed to "static"...
    assert sources["1.1.1.1"] == ["static"]
    assert sources["2.2.2.0/24"] == ["static"]
    assert sources["10.0.0.50/32"] == ["static"]
    # ...and even though 10.0.0.50/32 got compacted away into 10.0.0.0/24
    # alongside crawled addresses, containment-based attribution still
    # credits both the static entry and the crawl that produced 10.0.0.0/24.
    from sender_policy_flattener.formatting import attribute_sources

    assert attribute_sources("10.0.0.0/24", sources) == ["static", "test.com"]


@mock.patch(mocked_dns_object)
async def test_flatten_without_email_config_skips_email(mock_query, dns_responses):
    # No smtplib patch here on purpose: if flatten() tried to email despite
    # email_config=None, it would attempt a real SMTP connection and fail loudly.
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    lastresult = {"test.com": {"sum": "old", "records": ["v=spf1 -all"]}}
    actual, changed = await flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=None,
        lastresult=lastresult,
    )
    assert changed == ["test.com"]
    assert actual["test.com"]["sum"] != "old"


@mock.patch(mocked_dns_object)
async def test_flatten_writes_report_dir_on_change(mock_query, dns_responses, tmp_path):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    lastresult = {"test.com": {"sum": "old", "records": ["v=spf1 -all"]}}
    report_dir = tmp_path / "reports"
    actual, changed = await flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=None,
        lastresult=lastresult,
        report_dir=str(report_dir),
    )
    assert changed == ["test.com"]

    json_report = report_dir / "test.com.json"
    html_report = report_dir / "test.com.diff.html"
    bind_report = report_dir / "test.com.bind.txt"
    assert json_report.exists()
    assert html_report.exists()
    assert bind_report.exists()

    report_data = json.loads(json_report.read_text())
    assert report_data["previous"] == ["v=spf1 -all"]
    assert report_data["current"] == actual["test.com"]["records"]
    assert "Diff for test.com" in html_report.read_text()


@mock.patch(mocked_dns_object)
async def test_flatten_no_report_dir_writes_nothing(mock_query, dns_responses, tmp_path):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    lastresult = {"test.com": {"sum": "old", "records": ["v=spf1 -all"]}}
    report_dir = tmp_path / "reports"
    _actual, changed = await flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_config=None,
        lastresult=lastresult,
    )
    assert changed == ["test.com"]
    assert not report_dir.exists()


def _invoke_cli(mock_query, dns_responses, output_file, extra_args):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    return cli_runner.invoke(
        cli_app,
        [
            "--resolvers",
            "8.8.8.8",
            "--sending-domain",
            "test.com",
            "--domains",
            "test.com:txt",
            "--output",
            str(output_file),
            *extra_args,
        ],
    )


@mock.patch(mocked_dns_object)
def test_cli_fail_on_change_exits_nonzero(mock_query, dns_responses, tmp_path):
    output_file = tmp_path / "out.json"
    output_file.write_text(
        json.dumps({"test.com": {"sum": "old", "records": ["v=spf1 -all"]}})
    )
    result = _invoke_cli(
        mock_query, dns_responses, output_file, ["--fail-on-change"]
    )
    assert result.exit_code == 1


@mock.patch(mocked_dns_object)
def test_cli_without_fail_on_change_exits_zero_on_change(
    mock_query, dns_responses, tmp_path
):
    output_file = tmp_path / "out.json"
    output_file.write_text(
        json.dumps({"test.com": {"sum": "old", "records": ["v=spf1 -all"]}})
    )
    result = _invoke_cli(mock_query, dns_responses, output_file, [])
    assert result.exit_code == 0


@mock.patch(mocked_dns_object)
def test_cli_report_dir_writes_artifacts_and_fails(mock_query, dns_responses, tmp_path):
    output_file = tmp_path / "out.json"
    output_file.write_text(
        json.dumps({"test.com": {"sum": "old", "records": ["v=spf1 -all"]}})
    )
    report_dir = tmp_path / "reports"
    result = _invoke_cli(
        mock_query,
        dns_responses,
        output_file,
        ["--report-dir", str(report_dir), "--fail-on-change"],
    )
    assert result.exit_code == 1
    assert (report_dir / "test.com.json").exists()
    assert (report_dir / "test.com.diff.html").exists()
    assert (report_dir / "test.com.bind.txt").exists()


@mock.patch(mocked_dns_object)
def test_cli_no_change_exits_zero_even_with_fail_on_change(
    mock_query, dns_responses, tmp_path
):
    output_file = tmp_path / "out.json"
    # First run establishes the baseline result.
    first = _invoke_cli(mock_query, dns_responses, output_file, ["--fail-on-change"])
    assert first.exit_code == 0
    # Second run against the same (now up to date) baseline sees no change.
    second = _invoke_cli(mock_query, dns_responses, output_file, ["--fail-on-change"])
    assert second.exit_code == 0
