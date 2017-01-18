[![Build Status](https://api.travis-ci.org/cetanu/sender_policy_flattener.svg?branch=master)](https://travis-ci.org/cetanu/sender_policy_flattener)

sender_policy_flattener
=======================

We had a problem in our organisation that caused our SPF records to become invalid:

When customers computers were querying our SPF records, there were more than 10 lookups required after following all of the `include:` remarks.

Solution? Query them ourselves, and create a much more condense list of SPF records.

But wait... What if the upstream records change?
------------------------------------------------

Part of what the script does is that it creates a JSON file that keeps track of the last list of IP Addresses that your combination of SPF records had.

When the hashsum of your IP Addresses changes, it will send out an email (or just dump HTML if it can't find an email server) with a handy diff & BIND format for viewing what has changed, and promptly updating it.

You could theoretically extract the flat IP records from the resulting JSON file and automatically update your DNS configuration with it.

How do I use it?
----------------

Python 2.7, or 3.3+ is required.

Here's the usage:

    usage: sender_policy_flattener.py [-h] [-c CONFIG] [-r RESOLVERS] [-t TOADDR]
                                      [-f FROMADDR] [-s SUBJECT] [-d DOMAINS]
                                      [-o OUTPUT]

    optional arguments:
      -h, --help            show this help message and exit
      -c CONFIG, --config CONFIG
                            Name/path of JSON configuration file
      -r RESOLVERS, --resolvers RESOLVERS
                            Comma separated DNS servers to be used
      -t TOADDR, -to TOADDR
                            Recipient address for email alert
      -f FROMADDR, -from FROMADDR
                            Sending address for email alert
      -s SUBJECT, -subject SUBJECT
                            Subject string, must contain {zone}
      -d DOMAINS, --domains DOMAINS
                            Comma separated domain:rrtype to flatten to IP
                            addresses
      -o OUTPUT, --output OUTPUT
                            Name/path of output file

Example

    python sender_policy_flattener.py \
        --resolvers 8.8.8.8,8.8.4.4 \
        --to me@mydomain.com \
        --from admin@mydomain.com \
        --subject 'SPF for {zone} has changed!' \
        --domains 'gmail.com:txt,sendgrid.com:txt,yahoo.com:a'
        
or 

    python sender_policy_flattener.py --config spf.json

You can specify a config file, or you can specify all of the optional arguments from the command line.

I've provided a `settings.json` file with an example configuration file.


3rd party dependencies
----------------------

* netaddr
* dnspython

Example email format
--------------------

![Example screenshot](example/example.png)
