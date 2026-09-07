"""Pydantic models for validating sender_policy_flattener configuration files."""

import json
import sys
from pathlib import Path
from typing import Any

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

Domain = str
RRType = str


class EmailConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    to: EmailStr
    from_: EmailStr = Field(alias="from")
    subject: str
    server: str
    port: int | None = None
    use_tls: bool = False
    username: str | None = None
    password: str | None = None

    @field_validator("subject")
    @classmethod
    def _subject_has_zone(cls, value: str) -> str:
        if "{zone}" not in value:
            raise ValueError("subject must contain {zone}")
        return value


class AppConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sending_domains: dict[Domain, dict[Domain, RRType]] = Field(
        validation_alias=AliasChoices("sending_domains", "sending domains")
    )
    static_ips: list[str] | None = None
    resolvers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    email: EmailConfig | None = None
    output: str = "spf_sums.json"
    report_dir: str | None = None
    fail_on_change: bool = False


def load_config(path: str | Path) -> AppConfig:
    path = Path(path)
    data: dict[str, Any]
    if path.suffix == ".toml":
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    else:
        with path.open() as config_file:
            data = json.load(config_file)
    return AppConfig.model_validate(data)
