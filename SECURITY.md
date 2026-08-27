# Security Policy

## Scope

`agy-profile-linux` manages local Antigravity CLI authentication profiles on Linux. It handles OAuth credential files and can make authenticated requests to Google Cloud Code and Google user-info endpoints when the operator explicitly runs usage or identity refresh commands.

## Important credential warning

OAuth credentials are stored locally as owner-readable files with restrictive filesystem permissions. They are **not encrypted at rest** by this project. Protect the host, backups, snapshots, home directory, and any directory supplied through `--root`.

This project is not a password manager or a security boundary against a user with filesystem access, malware, root access, or compromised backups. Do not commit `.gemini/`, `.agy-profile-linux/`, token files, environment files, or copied credential material.

## Reporting a vulnerability

Please report security issues privately through [GitHub Security Advisories](https://github.com/googol55middle-alt/agy-profile-linux/security/advisories/new) when that feature is available.

Do not include OAuth tokens, refresh tokens, private keys, bearer headers, personal account data, or unredacted local paths in a report. Use synthetic credentials and a minimal reproduction whenever possible. If a private advisory cannot be opened, contact the repository maintainer through a private GitHub channel rather than opening a public issue.

## Supported security expectations

The project aims to:

- keep manager-controlled directories owner-private;
- reject unsafe symlink paths for managed files;
- avoid printing credential values and raw authenticated response content;
- use disposable homes for interactive login, model discovery, and isolated runs;
- avoid force-killing live `agy` processes during the explicit graceful-close operation;
- fail closed when managed state or authentication metadata is malformed.

These guarantees do not protect against a compromised operating system, a malicious `agy` binary selected by the operator, a malicious caller with access to the manager root, or changes in undocumented upstream authentication formats and endpoints.

## Safe disclosure and remediation

If a credential may have been exposed, revoke or replace it through the relevant provider before discussing the incident publicly. Preserve only sanitized logs and timestamps needed to investigate; never attach the affected credential file.
