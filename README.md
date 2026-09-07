sender policy flattener
=======================
Flattens SPF `include:`/`a`/`mx` chains into compact IP/CIDR blocks, so you
stay under the 10-lookup SPF limit. Tracks the last result in a JSON file;
when the flattened IPs change, it can email a diff, write change artifacts
to disk, and/or exit non-zero for CI.

Installation
--------------------

```shell
pip install sender_policy_flattener
```

Usage
----------------

```shell
spflat --help
```

No default config path — pass `-c/--config` (JSON or TOML, see `example/`),
or pass `--domains`/`--sending-domain` and friends directly instead. The two
are mutually exclusive: `--config` ignores any other CLI flags. Config keys
and CLI flags map 1:1 (see below).

```shell
spflat --resolvers 8.8.8.8,8.8.4.4 \
    --domains gmail.com:txt,sendgrid.com:txt,yahoo.com:a \
    --sending-domain mydomain.com \
    --to me@mydomain.com --from admin@mydomain.com \
    --subject 'SPF for {zone} has changed!'
```

#### Config file

`example/settings_example.toml` / `.json` — TOML recommended, JSON kept for
back-compat.

```toml
output = "sums.json"
resolvers = ["8.8.8.8", "8.8.4.4"]
static_ips = ["203.0.113.10", "203.0.113.11/32"]  # always-included, e.g. relays not visible via DNS

[sending_domains."mydomain.com"]
"yahoo.com" = "a"      # a:yahoo.com
"google.com" = "txt"   # include:google.com

[email]
to = "your@email.com"
from = "your@email.com"
subject = "[Change Detected] SPF Records for {zone} have changed."
server = "email_server"
use_tls = false
# username = "smtp-user"
# password = "smtp-pass"
```

`sending_domains` (JSON: `"sending domains"`) maps each domain you send as
to `{name: rrtype}`, one entry per `include:`/`a`/`mx` target. Multiple
top-level domains are processed independently in one run.

`email` is optional — omit it for no email alert. If given, `to`/`from`/
`subject`/`server` are required; `use_tls`/`username`/`password` aren't.
Bad/missing config fields raise a validation error naming the field.

#### CI / build-pipeline use

Instead of, or alongside, email:

```shell
spflat --config spf.toml --report-dir ./spf-report --fail-on-change
```

* `--report-dir DIR` (`report_dir`) — on change, writes
  `DIR/<domain>.json`, `.diff.html`, `.bind.txt` per sending domain.
* `--fail-on-change` (`fail_on_change`) — exit 1 if anything changed.

3rd party dependencies
----------------------
netaddr, dnspython, typer, pydantic, structlog, tenacity

Example email format
--------------------
<img src='https://raw.githubusercontent.com/cetanu/sender_policy_flattener/master/example/email_example.png' alt='example screenshot'></img>
