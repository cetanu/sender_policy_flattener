sender policy flattener
=======================
We had a problem in our organisation that caused our SPF records to become invalid:

When customers computers were querying our SPF records, there were more than 10 lookups required after following all of the ``include:`` remarks.

Solution? Query them ourselves, and create a much more condense list of SPF records.

#### But wait... What if the downstream records change?

Part of what the script does is that it creates a JSON file that keeps track of the last list of IP Addresses that your combination of SPF records had.

When the hashsum of your IP Addresses changes, it will send out an email (or just dump HTML if it can't find an email server) with a handy diff & BIND format for viewing what has changed, and promptly updating it.

You could theoretically extract the flat IP records from the resulting JSON file and automatically update your DNS configuration with it.

Installation
--------------------

#### via git clone

Clone this repo and run

```shell
pip install poetry
poetry install
```


#### via pip

```shell
pip install sender_policy_flattener
```


Usage
----------------

```
usage: spflat [-h] [-c CONFIG] [-r RESOLVERS] [-e MAILSERVER] [-t TOADDR]
              [-f FROMADDR] [-s SUBJECT] [-D SENDING_DOMAIN] [-d DOMAINS]
              [-o OUTPUT] [--static-ips STATIC_IPS]

A script that crawls and compacts SPF records into IP networks. This helps to
avoid exceeding the DNS lookup limit of the Sender Policy Framework (SPF)
https://tools.ietf.org/html/rfc7208#section-4.6.4

options:
  -h, --help            show this help message and exit
  -c, --config CONFIG   Name/path of JSON configuration file
  -r, --resolvers RESOLVERS
                        Comma separated DNS servers to be used
  -e, -mailserver MAILSERVER
                        Server to use for mailing alerts
  -t, -to TOADDR        Recipient address for email alert
  -f, -from FROMADDR    Sending address for email alert
  -s, -subject SUBJECT  Subject string, must contain {zone}
  -D, --sending-domain SENDING_DOMAIN
                        The domain which emails are being sent from
  -d, --domains DOMAINS
                        Comma separated domain:rrtype to flatten to IP
                        addresses. Imagine these are your SPF include
                        statements.
  -o, --output OUTPUT   Name/path of output file
  --static-ips STATIC_IPS
                        Comma separated IPs to be added to the SPF record
```

Note: there is no default config file location — `-c`/`--config` must point at
a JSON file you provide (see the ``settings.json`` example in this repo). If
you don't pass `-c`, you must instead pass every other flag on the command
line (`--domains`, `--sending-domain`, `--to`, `--from`, `--subject`,
`--mailserver`, at minimum).

Also note that flags containing a value with spaces (like `--subject`) must
be quoted as a single shell argument, e.g. `--subject 'SPF Flat'`, not
`--subject 'SPF' 'Flat'`.

Example

```shell
spflat --resolvers 8.8.8.8,8.8.4.4 \
    --to me@mydomain.com \
    --from admin@mydomain.com \
    --subject 'SPF for {zone} has changed!' \
    --domains gmail.com:txt,sendgrid.com:txt,yahoo.com:a \
    --sending-domain mydomain.com
```
or

```shell
spflat --config spf.json
```
You can specify a config file, or you can specify all of the optional arguments from the command line.

I've provided a ``settings.json`` file with an example configuration file.

#### Config file format

```json
{
    "sending domains": {
        "mydomain.com": {
            "yahoo.com": "a",
            "google.com": "txt",
            "apple.com": "txt",
            "reddit.com": "txt"
        },
        "myseconddomain.com": {
            "cisco.com": "a",
            "oculus.com": "a"
        }
    },
    "static_ips": ["203.0.113.10", "203.0.113.11/32"],
    "resolvers": ["8.8.8.8", "8.8.4.4"],
    "email": {
        "to": "your@email.com",
        "from": "your@email.com",
        "subject": "[Change Detected] SPF Records for {zone} have changed.",
        "server": "email_server"
    },
    "output": "sums.json"
}
```

``sending domains`` is a map of *each domain you send email as* to the list
of remote services/records that domain's SPF should flatten. You'll usually
only have one entry here (your own sending domain). A second top-level entry
like ``myseconddomain.com`` above is only needed if you send email as more
than one domain and want both flattened in a single run — each is processed
and reported on independently; it isn't nested under, or related to, the
first domain.

For each sending domain, the inner map is `{name: rrtype}` — the same thing
you'd write as `include:`, `a`, `mx`, etc. in a manual SPF record.
`"google.com": "txt"` means "flatten google.com's TXT (SPF) record", exactly
like `include:google.com`. `"yahoo.com": "a"` means "resolve yahoo.com's own
A record", like `a:yahoo.com`.

``static_ips`` (optional) is a flat list of IPs/CIDRs to always include in
every sending domain's output, regardless of what DNS resolves — useful for
mail relays or on-prem senders that aren't discoverable via any include/a/mx
lookup. Equivalent to the `--static-ips` CLI flag.


Supported Python versions
-------------------------
See the latest result of the build: https://github.com/cetanu/sender_policy_flattener/actions


3rd party dependencies
----------------------
* netaddr
* dnspython


Example email format
--------------------
<img src='https://raw.githubusercontent.com/cetanu/sender_policy_flattener/master/example/email_example.png' alt='example screenshot'></img>
