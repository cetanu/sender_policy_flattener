# coding=utf-8
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import structlog

from sender_policy_flattener.config import EmailConfig
from sender_policy_flattener.formatting import render_diff_html

# Type Aliases
Domain = str
EmailAddress = str
SPFRecord = str

log = structlog.get_logger(__name__)


def email_changes(
    zone: Domain,
    prev_addrs: list[SPFRecord],
    curr_addrs: list[SPFRecord],
    subject: str,
    config: EmailConfig,
    test: bool = False,
) -> str | None:
    html, bindformat = render_diff_html(zone, prev_addrs, curr_addrs)
    html_part = MIMEText(html, "html")
    msg_template = MIMEMultipart("alternative")
    msg_template["Subject"] = subject.format(zone=zone)
    msg_template["From"] = config.from_
    email = msg_template
    email.attach(html_part)

    try:
        port = config.port if config.port is not None else smtplib.SMTP_PORT
        with smtplib.SMTP(config.server, port) as mailserver:
            if config.use_tls:
                mailserver.starttls()
            if config.username and config.password:
                mailserver.login(config.username, config.password)
            mailserver.sendmail(config.from_, config.to, email.as_string())
    except Exception as err:
        log.warning("email_send_failed", error=str(err))
        with open("result.html", "w+") as mailfile:
            mailfile.write(html_part.as_string())
    if test:
        return bindformat
    return None
