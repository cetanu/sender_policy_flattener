# coding=utf-8
"""
A script that crawls and compacts SPF records into IP networks.
This helps to avoid exceeding the DNS lookup limit of the Sender Policy Framework (SPF)
https://tools.ietf.org/html/rfc7208#section-4.6.4
"""

import asyncio

import typer
from pydantic import ValidationError

import sender_policy_flattener
from sender_policy_flattener.config import AppConfig, load_config
from sender_policy_flattener.logging import configure_logging

# Type Aliases
Domain = str
RRType = str

app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def main(
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path of a JSON or TOML configuration file",
    ),
    resolvers: str = typer.Option(
        "8.8.8.8,8.8.4.4",
        "--resolvers",
        "-r",
        help="Comma separated DNS servers to be used",
    ),
    mailserver: str | None = typer.Option(
        None,
        "--mailserver",
        "-e",
        help="Server to use for mailing alerts",
    ),
    to: str | None = typer.Option(
        None,
        "--to",
        "-t",
        help="Recipient address for email alert",
    ),
    from_: str | None = typer.Option(
        None,
        "--from",
        "-f",
        help="Sending address for email alert",
    ),
    subject: str | None = typer.Option(
        None,
        "--subject",
        "-s",
        help="Subject string, must contain {zone}",
    ),
    sending_domain: str | None = typer.Option(
        None,
        "--sending-domain",
        "-D",
        help="The domain which emails are being sent from",
    ),
    domains: str | None = typer.Option(
        None,
        "--domains",
        "-d",
        help=(
            "Comma separated domain:rrtype to flatten to IP addresses. "
            "Imagine these are your SPF include statements."
        ),
    ),
    output: str = typer.Option(
        "spf_sums.json",
        "--output",
        "-o",
        help="Name/path of output file",
    ),
    static_ips: str | None = typer.Option(
        None,
        "--static-ips",
        help="Comma separated IPs to be added to the SPF record",
    ),
    use_tls: bool = typer.Option(
        False,
        "--use-tls",
        help="Use STARTTLS when connecting to the mail server",
    ),
    smtp_username: str | None = typer.Option(
        None,
        "--smtp-username",
        help="Username for SMTP authentication",
    ),
    smtp_password: str | None = typer.Option(
        None,
        "--smtp-password",
        help="Password for SMTP authentication",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    configure_logging(verbose)

    try:
        if config:
            app_config = load_config(config)
        else:
            sending_domains: dict[Domain, dict[Domain, RRType]] = {}
            if sending_domain and domains:
                spf_includes = [d.split(":") for d in domains.split(",")]
                sending_domains = {sending_domain: {d[0]: d[1] for d in spf_includes}}
            data = {
                "sending_domains": sending_domains,
                "resolvers": resolvers.split(","),
                "email": {
                    "to": to,
                    "from": from_,
                    "subject": subject,
                    "server": mailserver,
                    "use_tls": use_tls,
                    "username": smtp_username,
                    "password": smtp_password,
                },
                "output": output,
                "static_ips": static_ips.split(",") if static_ips else None,
            }
            app_config = AppConfig.model_validate(data)
    except ValidationError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=1)

    asyncio.run(sender_policy_flattener.run(app_config))


if __name__ == "__main__":
    app()
