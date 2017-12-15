# coding=utf-8
import unittest
import mock
from sender_policy_flattener import flatten
from sender_policy_flattener.crawler import crawl, spf2ips, default_resolvers
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.test.dns_mocks import dns_responses
from sender_policy_flattener.test.ip_fixtures import test_com_netblocks
from sender_policy_flattener.test.email_fmts import expected_final_email
from sender_policy_flattener.mechanisms import tokenize
from sender_policy_flattener.handlers import *

mocked_dns_object = 'sender_policy_flattener.crawler.resolver.Resolver.query'
expected_hash = '764567b38af1d413b346fd08df026e07bbcab6e70f73b039144900cc55fee1eb'


def MockDNSQuery(*args, **kwargs):
    rrecord, rrtype = args
    return dns_responses[rrtype][rrecord]


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


class HandlerTests(unittest.TestCase):
    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_ip(self, query):
        actual = [str(s) for s in handle_ip('172.16.0.1', 'test.com', default_resolvers)]
        expected = ['172.16.0.1']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_mx(self, query):
        actual = [str(s) for s in handle_mx(('mx', 'mx'), 'test.com', default_resolvers)]
        expected = ['192.168.0.10']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_mx_prefix(self, query):
        actual = [str(s) for s in handle_mx_prefix(['mx', '29'], 'test.com', default_resolvers)]
        expected = ['192.168.0.10/29']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_mx_domain(self, query):
        actual = [str(s) for s in handle_mx_domain('test.fake', 'test.com', default_resolvers)]
        expected = ['10.0.0.12',
                    '10.0.0.13']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_mx_domain_prefix(self, query):
        actual = [str(s) for s in handle_mx_domain_prefix(['test.fake', '27'], 'test.com', default_resolvers)]
        expected = ['10.0.0.12/27',
                    '10.0.0.13/27']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_a(self, query):
        actual = [str(s) for s in handle_a(('a', 'a'), 'test.com', default_resolvers)]
        expected = ['192.168.0.1']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_a_domain(self, query):
        actual = [str(s) for s in handle_a_domain('test.fake', 'test.com', default_resolvers)]
        expected = ['10.0.0.10',
                    '10.0.0.11']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_a_domain_prefix(self, query):
        actual = [str(s) for s in handle_a_domain_prefix(['test.fake', '24'], 'test.com', default_resolvers)]
        expected = ['10.0.0.10/24',
                    '10.0.0.11/24']
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_a_prefix(self, query):
        actual = [str(s) for s in handle_a_prefix(['a', '26'], 'test.com', default_resolvers)]
        expected = ['192.168.0.1/26']
        self.assertEqual(expected, actual)


class MechanismTests(unittest.TestCase):
    def test_a(self):
        actual = list(tokenize('v=spf1 a:test.com a a/28 a:test.com/27'))
        expected = [
            ('test.com', 'a_domain'),
            ('a', 'a'),
            (['a', '28'], 'a_prefix'),
            (['test.com', '27'], 'a_domain_prefix')
        ]
        self.assertEqual(expected, actual)

    def test_mx(self):
        actual = list(tokenize('v=spf1 mx:test.com mx mx/28 mx:test.com/27'))
        expected = [
            ('test.com', 'mx_domain'),
            ('mx', 'mx'),
            (['mx', '28'], 'mx_prefix'),
            (['test.com', '27'], 'mx_domain_prefix')
        ]
        self.assertEqual(expected, actual)

    def test_ptr(self):
        actual = list(tokenize('v=spf1 ptr ptr:1.1.1.1.in-addr.arpa'))
        expected = [
            ('ptr', 'ptr'),
            ('1.1.1.1.in-addr.arpa', 'ptr'),
        ]
        self.assertEqual(expected, actual)

    def test_include(self):
        actual = list(tokenize('v=spf1 include:spf.test.com'))
        expected = [
            ('spf.test.com', 'txt'),
        ]
        self.assertEqual(expected, actual)

    def test_exists(self):
        actual = list(tokenize('v=spf1 exists:validate.test.com'))
        expected = [
            ('validate.test.com', 'exists'),
        ]
        self.assertEqual(expected, actual)

    def test_ip(self):
        actual = list(tokenize('v=spf1 ip4:123.123.123.123 ip4:123.123.123.123/24 ip6:2001:4860:4000:: ip6:2001:4860:4000::/36'))
        expected = [
            ('123.123.123.123', 'ip'),
            ('123.123.123.123/24', 'ip'),
            ('2001:4860:4000::', 'ip'),
            ('2001:4860:4000::/36', 'ip'),
        ]
        self.assertEqual(expected, actual)


class SenderPolicyFlattenerTests(unittest.TestCase):
    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    def test_crawler_returns_all_expected_ips(self, query):
        actual = [str(s) for s in crawl('test.com', 'txt', 'test.com')]
        self.assertEqual(test_com_netblocks, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    def test_call_main_flatten_func(self, query, smtp):
        actual = flatten(
            input_records={
                'test.com': {
                    'test.com': 'txt'
                }
            },
            dns_servers=['8.8.8.8'],
            email_server='mocked',
            email_subject='{zone} has changed',
            fromaddress='mocked',
            toaddress='mocked',
        )
        expected_records = spf2ips({'test.com': 'txt'}, 'test.com')
        expected = {
            'test.com': {
                'records': expected_records,
                'sum': expected_hash
            }
        }
        self.assertEqual(expected, actual)

    @mock.patch(mocked_dns_object, side_effect=MockDNSQuery)
    @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    def test_bind_format_has_one_pair_of_parens_per_record(self, query, smtp):
        expected_records = spf2ips({'test.com': 'txt'}, 'test.com')
        actual = email_changes(
            zone='test.com',
            prev_addrs=[],
            curr_addrs=expected_records,
            subject='{zone} has changed',
            server='mocked',
            fromaddr='mocked',
            toaddr='mocked',
            test=True,
        )
        self.assertEqual(actual.count('('), actual.count('IN TXT'))
        self.assertEqual(actual.count(')'), actual.count('IN TXT'))
