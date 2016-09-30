""" Yes, just one file for tests will do. """
import unittest
import json
import random
from string import printable
import sender_policy_flattener as spf


class FlattenerTests(unittest.TestCase):
    def test_hashseq_produces_consistent_hash(self):
        jumbled = random.sample(printable, len(printable))
        self.assertTrue(spf.hash_seq(jumbled) == spf.hash_seq(printable))

class SettingsTests(unittest.TestCase):
    def setUp(self):
        with open('settings.json') as f:
            self.settings = json.load(f)

    def test_settings_contains_min_details(self):
        min_keys = ['sending domains', 'email', 'output']
        for key in min_keys:
            self.assertIn(key, self.settings.keys())

    def test_email_settings_contains_min_details(self):
        min_keys = ['to', 'from', 'subject', 'server']
        for key in min_keys:
            self.assertIn(key, self.settings['email'].keys())
