# Local hardening notes

This is an independent Linux fork based on upstream `agy-cli-manager` 0.2.1. It is not affiliated with the upstream maintainers, Google, or Antigravity.

## Security changes

- Account labels are validated and cannot escape the account store.
- Manager-controlled directories use `0700`; state, token, and project-cache files use `0600`.
- State and copied credential files are replaced atomically.
- Manager paths, account directories, managed cache directories, state, and lock files reject symlinks.
- The account-bound `default_project_id.txt` moves with its OAuth profile.
- Invalid or malformed OAuth token files are rejected during import.
- Import does not send saved access tokens to Google merely to identify an account.
- Automatic `--dangerously-skip-permissions` warmups are disabled.
- Login, model lookup, and identity probing use disposable homes instead of the existing CLI home.

## Runtime model

The normal `switch <name>` command follows the Windows `agy-profile` design. It updates only the live OAuth credential and account-bound project ID in the normal `~/.gemini` home. Settings, conversations, knowledge, skills, MCP configuration, and other shared files are not copied or replaced.

Before a live switch, the manager:

- holds the manager lock;
- by default checks that no matching live-home `agy` process is running and refuses if one is found;
- with explicit `--close`, sends `SIGTERM` only to same-user `agy` processes whose `HOME` is the live home;
- waits for graceful exit and never force-kills;
- creates a private rollback snapshot of the two managed files;
- applies the selected account;
- restores the snapshot if the file update or state update fails.

Use it like this:

```bash
agy-profile-linux save personal
agy-profile-linux switch work
agy
```

`run -- <agy arguments>` remains available when you explicitly want a disposable isolated home. `switch <name> --isolated` changes only the manager's isolated runtime and does not touch the normal home.

A direct `agy` command uses the normal home. After a live switch, that is the intended command to run.

## Migration from an earlier local installation

If state from an older build contains a `live_dir`, clear it with:

```bash
agy-profile-linux set-live-dir
```

Passing a path to `set-live-dir` is intentionally rejected. If an old `live_dir` remains, credential-changing operations fail closed rather than write into it.

Imports must name their source explicitly:

```bash
agy-profile-linux import-current primary /path/to/.gemini
```

## Safe operating rules

1. Keep switching in `manual` mode unless you deliberately review automatic behavior.
2. Use `run` (or an installed wrapper for it) for managed `agy` sessions.
3. Do not run `refresh-usage` unless you want an authenticated quota request to Google.
4. If an import reports invalid authentication data, use `login <label>` for a normal interactive sign-in. Do not edit token files by hand.
5. The manager stores only the OAuth token and account-bound project cache. It leaves ordinary `.gemini` configuration and logs outside the isolated runtime.
