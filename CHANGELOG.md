# Changelog

## v0.1.0

- publish the Linux-focused `agy-profile-linux` distribution and CLI entrypoint
- rename the Python package to `agy_profile_linux`
- add credential-only live switching for the normal Linux `agy` home
- add explicit graceful close support with `switch --close`
- preserve shared `.gemini` data and directory modes during live switching
- add atomic rollback, symlink defenses, redacted errors, and hardening regression tests
- retain the MIT license and credit the upstream `agy-cli-manager` base

## v0.2.1 - 2026-07-15

- preserve the explicit profile name supplied during login

## v0.2.0 - 2026-07-01

- add account model discovery via Python API and `agy-profile-linux models --json`
- add `refresh-due` for non-interactive due-account usage refresh
- improve identity detection with local Antigravity log parsing
- expand README with first-run setup, API usage, and a sanitized dashboard screenshot
- add MIT license
