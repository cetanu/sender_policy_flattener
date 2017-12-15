# coding=utf-8
import unittest
import mock
from sender_policy_flattener import flatten
from sender_policy_flattener.crawler import SPFCrawler
from sender_policy_flattener.email_utils import email_changes
from sender_policy_flattener.test.dns_mocks import dns_responses
from sender_policy_flattener.test.ip_fixtures import test_com_netblocks
from sender_policy_flattener.test.email_fmts import expected_final_email


expected_hash = '96e230215f3c3906016794f0f2d7d32306e152095fc6f4d09ea0bcbc116044e3'

def MockDNSQuery(*args, **kwargs):
    rrecord, rrtype = args
    class MockResponse(object):
        class response(object):
            @staticmethod
            def to_text():
                return dns_responses[rrecord]
    return MockResponse()


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


class SenderPolicyFlattenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crawler = SPFCrawler(['notused'])

    @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    def test_crawler_returns_all_expected_ips(self, query):
        result = list(self.crawler._crawl('test.com', 'txt'))
        self.assertEqual(result, test_com_netblocks)

    @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    def test_call_main_flatten_func(self, query, smtp):
        result = flatten(
            input_records={
                'sender.domain.com': {
                    'test.com': 'txt'
                }
            },
            dns_servers=['notused'],
            email_server='mocked',
            email_subject='{zone} has changed',
            fromaddress='mocked',
            toaddress='mocked',
        )
        expected_records = self.crawler.spf2ips({'test.com': 'txt'}, 'sender.domain.com')
        expected_result = {
            'sender.domain.com': {
                'records': expected_records,
                'sum': expected_hash
            }
        }
        self.assertEqual(result, expected_result)

    @mock.patch('sender_policy_flattener.crawler.resolver.Resolver.query', side_effect=MockDNSQuery)
    @mock.patch('sender_policy_flattener.email_utils.smtplib', side_effect=MockSmtplib)
    def test_bind_format_doesnt_dupe_parenthesis(self, query, smtp):
        expected_records = self.crawler.spf2ips({'test.com': 'txt'}, 'sender.domain.com')
        result = email_changes(
            zone='sender.domain.com',
            prev_addrs=[],
            curr_addrs=expected_records,
            subject='{zone} has changed',
            server='mocked',
            fromaddr='mocked',
            toaddr='mocked',
            test=True,
        )
        self.assertEqual(result, expected_final_email)
