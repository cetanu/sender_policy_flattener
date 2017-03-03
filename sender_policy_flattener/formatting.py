# coding=utf-8
import hashlib


def wrap_in_spf_tokens(domain, ipv4blocks, last_record):
    for spf_num, spf_set in enumerate(ipv4blocks):
        spf_set = ' '.join(spf_set)
        if spf_num == last_record:
            spfrecord = 'v=spf1 {0} -all'.format(spf_set)
        else:
            spfrecord = 'v=spf1 {0} include:spf{1}.{2} -all'.format(spf_set, spf_num + 1, domain)
        yield spfrecord


def format_rrecord_value_for_bind(spfrec):
    spfrec = spfrec.split()
    yield '( '
    while spfrec:
        line, end = '"', '"'
        try:
            for i in range(4):
                line += spfrec.pop(0) + ' '
        except IndexError:
            end = '"'
        finally:
            yield line + end
    yield ' )'


def sequence_hash(iterable):
    flat_sorted_sequence = ' '.join(sorted([token for string in iterable for token in string.split()]))
    return hashlib.sha256(flat_sorted_sequence.encode()).hexdigest()
