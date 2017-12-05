# coding=utf-8
import unittest
import json
import random
from string import printable
from sender_policy_flattener.crawler import SPFCrawler
from sender_policy_flattener.regexes import dig_answer, ipv4, spf_ip, spf_txt_or_include
from sender_policy_flattener.formatting import wrap_in_spf_tokens, format_records_for_email, sequence_hash


class FlattenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('tests/fixtures.json') as f:
            cls.fixtures = json.load(f)
        cls.response = cls.fixtures['dns_regex']['response']
        cls.answer = cls.fixtures['dns_regex']['answer_section']
        cls.crawler = SPFCrawler(['8.8.8.8', '8.8.4.4'])

    def test_hashseq_produces_consistent_hash(self):
        jumbled = random.sample(printable, len(printable))
        self.assertTrue(sequence_hash(jumbled) == sequence_hash(printable))

    def test_answer_section_is_extracted_from_dns_response(self):
        expected = self.fixtures['dns_regex']['answer_section']
        match = dig_answer.search(self.response).group()
        self.assertEqual(match, expected)

    def test_ipaddresses_are_extracted_from_regex_search(self):
        expected = self.fixtures['dns_regex']['ips']
        match = spf_ip.findall(self.answer)
        self.assertEqual(match, expected)

    def test_a_records_are_extracted_from_regex_search(self):
        expected = self.fixtures['dns_regex']['a_record']
        match = ipv4.findall(self.answer)
        self.assertEqual(match, expected)

    # def test_cname_records_are_extracted_from_regex_search(self):
    #     pass

    def test_includes_are_extracted_from_regex_search(self):
        expected = self.fixtures['dns_regex']['includes']
        match = spf_txt_or_include.findall(self.answer)  # Tuple(Tuple(Str, Str), ...)
        match = [list(l) for l in match]
        self.assertListEqual(match, expected)

    def test_ipaddresses_are_separated_correctly(self):
        ips = self.fixtures['flattening']['ips']
        ipblocks, lastrec = self.crawler._split_at_450bytes(ips)
        ipblocks = [list(x) for x in ipblocks]
        ipblocks = sequence_hash(repr(ipblocks))
        
        expected_ipblocks = self.fixtures['flattening']['separated']
        expected_ipblocks = sequence_hash(repr(expected_ipblocks))
        expected_lastrec = self.fixtures['flattening']['lastrec']
        
        self.assertEqual(ipblocks, expected_ipblocks)        
        self.assertEqual(lastrec, expected_lastrec)
        
    def test_bind_compatible_format_doesnt_dupe_parens(self):
        ips = self.fixtures['flattening']['ips']
        expected_num_of_records = len(self.fixtures['flattening']['separated'])
        ipblocks, lastrec = self.crawler._split_at_450bytes(ips)
        records = [record for record in wrap_in_spf_tokens('unittest.com', ipblocks, lastrec)]
        bindformat = format_records_for_email(records)
        self.assertEqual(bindformat.count('('), expected_num_of_records)
        self.assertEqual(bindformat.count(')'), expected_num_of_records)


class SettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('example/settings_example.json') as f:
            cls.settings = json.load(f)

    def test_settings_contains_min_details(self):
        min_keys = ['sending domains', 'email', 'output']
        for key in min_keys:
            self.assertIn(key, self.settings.keys())

    def test_email_settings_contains_min_details(self):
        min_keys = ['to', 'from', 'subject', 'server']
        for key in min_keys:
            self.assertIn(key, self.settings['email'].keys())
