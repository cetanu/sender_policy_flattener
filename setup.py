# coding=utf-8
from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='sender_policy_flattener',
    version='0.2.4',
    packages=['sender_policy_flattener'],
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
    ],
    keywords='spf dns sender policy framework',
    url='https://github.com/cetanu/sender_policy_flattener',
    license='MIT',
    author='vsyrakis',
    author_email='cetanu@gmail.com',
    description='Condense SPF records to network blocks to avoid DNS Lookup Limits',
    scripts=[
        'bin/spflat'
    ],
    install_requires=[
        'netaddr',
        'dnspython',
    ],
    test_suite='nose.collector',
    test_require=['nose']
)
