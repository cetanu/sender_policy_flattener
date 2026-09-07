# Changelog

## [0.5.0](https://github.com/cetanu/sender_policy_flattener/compare/v0.4.1...v0.5.0) (2026-09-07)


### Features

* make email alerts optional, add --report-dir/--fail-on-change for CI use ([935276b](https://github.com/cetanu/sender_policy_flattener/commit/935276bba54543c2ec18697c25cf2ac580f014de))
* modernize CLI onto typer/pydantic/structlog with async DNS crawling ([6d16460](https://github.com/cetanu/sender_policy_flattener/commit/6d164606436f2d4ff79202d31c5ddef876da766d))


### Bug Fixes

* **crawler:** resolve A/MX records for top-level sending-domain entries ([28f60b4](https://github.com/cetanu/sender_policy_flattener/commit/28f60b40a5e8df6dc058bcaa04d33c6ad36d6580))
* **deps:** bump pytest and pygments to patch known vulnerabilities ([a78e950](https://github.com/cetanu/sender_policy_flattener/commit/a78e9503678f28f94863ab9dbeb5c283bb06ce36))


### Documentation

* document config file semantics and static_ips ([a37e746](https://github.com/cetanu/sender_policy_flattener/commit/a37e746e7dccd5729c61277604bf1608f5e8d119))
* rewrite README tersely, cover TOML config and new CLI options ([a5c9eee](https://github.com/cetanu/sender_policy_flattener/commit/a5c9eee2c72f704c0686df6a3c0d5f2c5e04d0fe))

## [0.4.1](https://github.com/cetanu/sender_policy_flattener/compare/sender_policy_flattener-v0.4.0...sender_policy_flattener-v0.4.1) (2026-09-07)


### Bug Fixes

* **crawler:** resolve A/MX records for top-level sending-domain entries ([28f60b4](https://github.com/cetanu/sender_policy_flattener/commit/28f60b40a5e8df6dc058bcaa04d33c6ad36d6580))
* **deps:** bump pytest and pygments to patch known vulnerabilities ([a78e950](https://github.com/cetanu/sender_policy_flattener/commit/a78e9503678f28f94863ab9dbeb5c283bb06ce36))


### Documentation

* document config file semantics and static_ips ([a37e746](https://github.com/cetanu/sender_policy_flattener/commit/a37e746e7dccd5729c61277604bf1608f5e8d119))
