# coding=utf-8
import unittest
import mock
from sender_policy_flattener import flatten
from sender_policy_flattener.crawler import crawl
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.test.dns_mocks import dns_responses
from sender_policy_flattener.test.ip_fixtures import test_com_netblocks
from sender_policy_flattener.test.email_fmts import expected_final_email
from sender_policy_flattener.mechanisms import tokenize


expected_hash = 'c8fdf498bf282b7cd5ec563e4df2b2cdc609f7f69aa1f7acf6c97974d82eaa0c'

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
    @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    def test_crawler_returns_all_expected_ips(self, query):
        actual = list(crawl('test.com', 'txt', 'sender.com'))
        self.assertEqual(test_com_netblocks, actual)

    # @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    # @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    # def test_call_main_flatten_func(self, query, smtp):
    #     actual = flatten(
    #         input_records={
    #             'sender.domain.com': {
    #                 'test.com': 'txt'
    #             }
    #         },
    #         dns_servers=['notused'],
    #         email_server='mocked',
    #         email_subject='{zone} has changed',
    #         fromaddress='mocked',
    #         toaddress='mocked',
    #     )
    #     expected_records = self.crawler.spf2ips({'test.com': 'txt'}, 'sender.domain.com')
    #     expected = {
    #         'sender.domain.com': {
    #             'records': expected_records,
    #             'sum': expected_hash
    #         }
    #     }
    #     self.assertEqual(expected, actual)
    #
    # @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    # @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    # def test_bind_format_doesnt_dupe_parenthesis(self, query, smtp):
    #     expected_records = self.crawler.spf2ips({'test.com': 'txt'}, 'sender.domain.com')
    #     actual = email_changes(
    #         zone='sender.domain.com',
    #         prev_addrs=[],
    #         curr_addrs=expected_records,
    #         subject='{zone} has changed',
    #         server='mocked',
    #         fromaddr='mocked',
    #         toaddr='mocked',
    #         test=True,
    #     )
    #     self.assertEqual(expected_final_email, actual)
