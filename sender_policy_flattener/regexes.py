# coding=utf-8
import re

dig_answer = re.compile(r'ANSWER\n(?P<answers>[^;]+)')
ipv4 = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})')
spf_ip = re.compile(r'(?<=ip[46]:)\S+')
spf_txt_or_include = re.compile(r'(?P<type>include|a|mx(?: \d+)? ?|ptr|cname ?)[:](?P<hostname>[^\s\'\"]+\w)', flags=re.IGNORECASE)
spf_token = re.compile(r'(include|spf|all)')
