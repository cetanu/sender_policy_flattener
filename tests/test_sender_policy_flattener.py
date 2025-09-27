# coding=utf-8
from dns.resolver import NXDOMAIN, NoAnswer, Resolver
import mock
from sender_policy_flattener import flatten
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
    handler_mapping,
    prefix_handler_mapping,
)



mocked_dns_object = "sender_policy_flattener.crawler.resolver.Resolver.query"
expected_hash = "764567b38af1d413b346fd08df026e07bbcab6e70f73b039144900cc55fee1eb"
expected_large_hash = "103c78c52ee89aab2f55a32337d942191589c41613ab312279d050b63e774334"


def MockDNSQuery(dns_responses, *args, **kwargs):
    rrecord, rrtype = args
    rrecord = str(rrecord)
    # normalize MX records "10 <domain>" to "<domain>"
    rrecord = rrecord.split()[-1]
    # remove TLD dot from all domains
    if rrecord.endswith("."):
        rrecord = rrecord.rstrip(".")
    _type = dns_responses[rrtype]
    _record = _type[rrecord]
    return _record


def MockSmtplib(*args, **kwargs):
    class MockResponse(object):
        class SMTP(object):
            @staticmethod
            def connect():
                return True

            @staticmethod
            def sendmail():
                return True

    return MockResponse()


@mock.patch(mocked_dns_object)
def test_ip(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) for s in handle_ip("172.16.0.1", "test.com", default_resolvers)]
    expected = ["172.16.0.1"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_mx(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) for s in handle_mx(("mx", "mx"), "test.com", default_resolvers)]
    expected = ["192.168.0.10"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_mx_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s) for s in handle_mx_prefix(["mx", "29"], "test.com", default_resolvers)
    ]
    expected = ["192.168.0.10/29"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_mx_domain(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s) for s in handle_mx_domain("test.fake", "test.com", default_resolvers)
    ]
    expected = ["10.0.0.12", "10.0.0.13"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_mx_domain_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        for s in handle_mx_domain_prefix(
            ["test.fake", "27"], "test.com", default_resolvers
        )
    ]
    expected = ["10.0.0.12/27", "10.0.0.13/27"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_a(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) for s in handle_a(("a", "a"), "test.com", default_resolvers)]
    expected = ["192.168.0.1"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_a_domain(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s) for s in handle_a_domain("test.fake", "test.com", default_resolvers)
    ]
    expected = ["10.0.0.10", "10.0.0.11"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_a_domain_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s)
        for s in handle_a_domain_prefix(
            ["test.fake", "24"], "test.com", default_resolvers
        )
    ]
    expected = ["10.0.0.10/24", "10.0.0.11/24"]
    assert expected == actual


@mock.patch(mocked_dns_object)
def test_a_prefix(mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [
        str(s) for s in handle_a_prefix(["a", "26"], "test.com", default_resolvers)
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
def test_crawler_returns_all_expected_ips(
    mock_query, dns_responses, test_com_netblocks
):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = [str(s) for s in crawl("test.com", "txt", "test.com")]
    assert test_com_netblocks == actual





@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", side_effect=MockSmtplib)
def test_call_main_flatten_func(mock_smtp, mock_query, dns_responses):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = flatten(
        input_records={"test.com": {"test.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_server="mocked",
        email_subject="{zone} has changed",
        fromaddress="mocked",
        toaddress="mocked",
    )

    resolvers = Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = spf2ips({"test.com": "txt"}, "test.com", resolvers=resolvers)
    expected = {"test.com": {"records": expected_records, "sum": expected_hash}}
    assert expected == actual


@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", side_effect=MockSmtplib)
def test_call_main_flatten_func_on_large_spf_records(
    mock_smtp, mock_query, dns_responses
):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)
    actual = flatten(
        input_records={"test.com": {"galactus.com": "txt"}},
        dns_servers=["8.8.8.8"],
        email_server="mocked",
        email_subject="{zone} has changed",
        fromaddress="mocked",
        toaddress="mocked",
    )

    resolvers = Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = spf2ips({"galactus.com": "txt"}, "test.com", resolvers=resolvers)
    expected = {"test.com": {"records": expected_records, "sum": expected_large_hash}}
    assert expected == actual


@mock.patch(mocked_dns_object)
@mock.patch("sender_policy_flattener.email_utils.smtplib", side_effect=MockSmtplib)
def test_bind_format(mock_smtp, mock_query, dns_responses, expected_final_email):
    mock_query.side_effect = lambda *a, **kw: MockDNSQuery(dns_responses, *a, **kw)

    resolvers = Resolver()
    resolvers.nameservers = ["8.8.8.8"]
    expected_records = spf2ips({"test.com": "txt"}, "test.com", resolvers=resolvers)
    actual = email_changes(
        zone="test.com",
        prev_addrs=[],
        curr_addrs=expected_records,
        subject="{zone} has changed",
        server="mocked",
        fromaddr="mocked",
        toaddr="mocked",
        test=True,
    )
    assert actual
    assert actual.count("(") == actual.count("IN TXT")
    assert actual.count(")") == actual.count("IN TXT")
    assert expected_final_email == actual
