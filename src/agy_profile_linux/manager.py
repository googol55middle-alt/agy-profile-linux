from __future__ import annotations

import base64
import contextvars
import json
import os
import re
import secrets
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
from contextlib import contextmanager

import fcntl


MANAGED_PROFILE_FILES = (
    "antigravity-cli/antigravity-oauth-token",
    "antigravity-cli/cache/default_project_id.txt",
)
LOGIN_ARTIFACT_SETS = (
    ("antigravity-cli/antigravity-oauth-token",),
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
APPLY_AUTH_EMAIL_PATTERN = re.compile(r"applyAuthResult:\s+email=([^,\s]+)", re.IGNORECASE)
MODEL_LABEL_ALLOWED_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+:/()\-]{0,159}$")
MODEL_LABEL_FAMILY_PATTERN = re.compile(
    r"\b(?:gemini|claude|gpt|llama|mistral|deepseek|qwen|codestral|phi|command|nova)\b",
    re.IGNORECASE,
)
ACCOUNT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@ -]{0,95}\Z")
DEFAULT_REFRESH_POLICY_SECONDS = 1800
USAGE_WINDOW_NAMES = ("short", "weekly")
DEFAULT_SWITCH_MODE = "manual"
VALID_SWITCH_MODES = ("auto", "manual")
DEFAULT_REFRESH_FAILURE_SWITCH_THRESHOLD = 2
DEFAULT_SHORT_SWITCH_THRESHOLD_PERCENT = 10.0
DEFAULT_CANDIDATE_STRATEGY = "balanced"
VALID_CANDIDATE_STRATEGIES = ("balanced", "highest-short", "round-robin")
DEFAULT_SWITCH_DEDUPE_SECONDS = 15
DEFAULT_SWITCH_HISTORY_LIMIT = 20
MAX_IDENTITY_LOG_BYTES = 1_000_000
SAFE_FAILURE_REASONS = frozenset(
    {
        "active_missing",
        "authentication_failed",
        "no_active_account",
        "quota_exhausted",
        "request_failed",
    }
)
DEFAULT_FAILURE_REASON = "caller_reported_failure"
_MANAGER_LOCK_ROOTS: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "agy_manager_lock_roots", default=()
)
LIVE_DIR_SYNC_DISABLED_MESSAGE = (
    "Live-profile synchronization is disabled in this hardened build. "
    "Use the isolated `run` command instead."
)
CODE_ASSIST_BASE_URL = "https://cloudcode-pa.googleapis.com"
CODE_ASSIST_USER_AGENT = "antigravity"
CODE_ASSIST_LOAD_PATH = "/v1internal:loadCodeAssist"
CODE_ASSIST_QUOTA_PATH = "/v1internal:retrieveUserQuota"
CODE_ASSIST_QUOTA_SUMMARY_PATH = "/v1internal:retrieveUserQuotaSummary"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def _normalize_failure_reason(reason: object) -> str:
    if isinstance(reason, str) and reason in SAFE_FAILURE_REASONS:
        return reason
    return DEFAULT_FAILURE_REASON


@dataclass
class ManagerPaths:
    root: Path
    accounts_dir: Path
    state_file: Path
    runtime_dir: Path
    lock_file: Path


@dataclass
class RotationResult:
    previous_active: str | None
    active: str | None
    switched_to: str | None
    marked_bad: bool
    reason: str | None
    cooldown_minutes: int
    outcome: str = "unknown"


@dataclass
class UsageRefreshResult:
    account: str
    source_home: str
    project_id: str | None
    plan_type: str | None
    prompt_credits_available: int | float | None
    prompt_credits_monthly: int | float | None
    short_usage_status: str
    short_usage_value: float | None
    short_reset_at: str | None
    weekly_usage_status: str
    weekly_usage_value: float | None
    weekly_reset_at: str | None
    bucket_count: int


@dataclass
class EnsureActiveResult:
    triggered: bool
    switch_mode: str
    previous_active: str | None
    active: str | None
    switched_to: str | None
    reason: str | None
    cooldown_minutes: int


def _parse_model_label(value: str) -> dict | None:
    label = value.strip()
    if not label or not MODEL_LABEL_ALLOWED_PATTERN.fullmatch(label):
        return None
    if not MODEL_LABEL_FAMILY_PATTERN.search(label):
        return None
    variant = None
    base = label
    match = re.match(r"^(?P<base>.+?) \((?P<variant>[^()]+)\)$", label)
    if match:
        base = match.group("base").strip()
        variant = match.group("variant").strip()
    provider = None
    family = None
    parts = base.split(None, 1)
    if parts:
        provider = parts[0].strip() or None
    if len(parts) > 1:
        family = parts[1].strip() or None
    return {
        "name": label,
        "provider": provider,
        "family": family,
        "variant": variant,
    }


def default_root() -> Path:
    return Path.home() / ".agy-profile-linux"


def build_paths(root: Path) -> ManagerPaths:
    return ManagerPaths(
        root=root,
        accounts_dir=root / "accounts",
        state_file=root / "state.json",
        runtime_dir=root / "runtime",
        lock_file=root / "manager.lock",
    )


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _no_follow_flags() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if value is None:
        raise ValueError("This platform cannot safely open manager files without following symlinks.")
    return value


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    if directory is None:
        raise ValueError("This platform cannot safely open manager directories.")
    return os.O_RDONLY | directory | _no_follow_flags() | getattr(os, "O_CLOEXEC", 0)


def _validate_path_component(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError("Invalid manager path component.")


def _stat_at(parent_fd: int, name: str) -> os.stat_result | None:
    _validate_path_component(name)
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("Unable to inspect a manager path safely.") from exc


def _open_child_directory_fd(
    parent_fd: int,
    name: str,
    *,
    create: bool = False,
    private: bool = False,
) -> int:
    _validate_path_component(name)
    existing = _stat_at(parent_fd, name)
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise ValueError("Unsafe symlink manager directory.")
    if existing is not None and not stat.S_ISDIR(existing.st_mode):
        raise ValueError("Expected a manager directory.")
    try:
        fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise ValueError("Expected directory does not exist.")
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError("Unable to safely create a manager directory.") from exc
    except OSError as exc:
        raise ValueError("Unable to safely open a manager directory.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Expected a manager directory.")
        if private:
            os.fchmod(fd, 0o700)
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_directory_fd_no_follow(
    path: Path,
    *,
    create: bool = False,
    private_final: bool = False,
) -> int:
    absolute = _absolute_path(path)
    parts = absolute.parts[1:]
    root_fd = os.open(absolute.anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    current_fd = root_fd
    try:
        for index, part in enumerate(parts):
            next_fd = _open_child_directory_fd(
                current_fd,
                part,
                create=create,
                private=private_final and index == len(parts) - 1,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _open_parent_directory_fd(
    path: Path,
    *,
    create_parent: bool = False,
    private_parent: bool = False,
) -> tuple[int, str]:
    absolute = _absolute_path(path)
    name = absolute.name
    _validate_path_component(name)
    parent_fd = _open_directory_fd_no_follow(
        absolute.parent,
        create=create_parent,
        private_final=private_parent,
    )
    return parent_fd, name


def _assert_no_symlink_components(path: Path) -> Path:
    absolute = _absolute_path(path)
    if absolute == Path(absolute.anchor):
        return absolute
    parent_fd, name = _open_parent_directory_fd(absolute)
    try:
        info = _stat_at(parent_fd, name)
        if info is not None and stat.S_ISLNK(info.st_mode):
            raise ValueError(f"Unsafe symlink path: {absolute}")
    finally:
        os.close(parent_fd)
    return absolute


def _assert_real_directory(path: Path) -> Path:
    absolute = _absolute_path(path)
    fd = _open_directory_fd_no_follow(absolute)
    os.close(fd)
    return absolute


def _assert_regular_file_or_missing(path: Path) -> Path:
    absolute = _absolute_path(path)
    parent_fd, name = _open_parent_directory_fd(absolute)
    try:
        info = _stat_at(parent_fd, name)
        if info is None:
            return absolute
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"Unsafe symlink path: {absolute}")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Expected regular file: {absolute}")
        return absolute
    finally:
        os.close(parent_fd)


def _ensure_regular_or_missing_at(parent_fd: int, name: str) -> None:
    info = _stat_at(parent_fd, name)
    if info is None:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("Unsafe symlink manager file.")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Expected regular manager file.")


def _open_regular_no_follow(path: Path, flags: int, *, mode: int = 0o600) -> int:
    parent_fd, name = _open_parent_directory_fd(path)
    try:
        _ensure_regular_or_missing_at(parent_fd, name)
        try:
            fd = os.open(
                name,
                flags | _no_follow_flags() | getattr(os, "O_CLOEXEC", 0),
                mode,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise ValueError("Unable to safely open a manager file.") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Expected regular manager file.")
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


def _ensure_private_directory(path: Path) -> None:
    fd = _open_directory_fd_no_follow(path, create=True, private_final=True)
    os.close(fd)


def _ensure_private_child_directory(root: Path, path: Path) -> None:
    root_absolute = _absolute_path(root)
    path_absolute = _absolute_path(path)
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise ValueError(f"Managed path escapes its root: {path_absolute}") from exc
    current_fd = _open_directory_fd_no_follow(root_absolute, create=True, private_final=True)
    try:
        for part in relative.parts:
            next_fd = _open_child_directory_fd(current_fd, part, create=True, private=True)
            os.close(current_fd)
            current_fd = next_fd
    finally:
        os.close(current_fd)


def _read_private_text(path: Path) -> str:
    fd = _open_regular_no_follow(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        return f.read()


def _read_regular_text_at(parent_fd: int, name: str) -> str | None:
    info = _stat_at(parent_fd, name)
    if info is None:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("Unsafe symlink manager file.")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Expected regular manager file.")
    if info.st_size > MAX_IDENTITY_LOG_BYTES:
        raise ValueError("Identity log file exceeds the safe size limit.")
    try:
        fd = os.open(
            name,
            os.O_RDONLY | _no_follow_flags() | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ValueError("Unable to safely open a manager file.") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(info, opened):
            raise ValueError("Manager log changed during read.")
        if opened.st_size > MAX_IDENTITY_LOG_BYTES:
            raise ValueError("Identity log file exceeds the safe size limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_IDENTITY_LOG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_IDENTITY_LOG_BYTES:
                raise ValueError("Identity log file exceeds the safe size limit.")
        latest = os.fstat(fd)
        if (
            not _same_inode(info, latest)
            or latest.st_size != info.st_size
            or latest.st_mtime_ns != info.st_mtime_ns
        ):
            raise ValueError("Manager log changed during read.")
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError as exc:
        raise ValueError("Unable to safely read a manager log.") from exc
    finally:
        os.close(fd)


def _new_temporary_file_at(parent_fd: int, prefix: str) -> tuple[int, str]:
    for _ in range(32):
        name = f".{prefix}-{secrets.token_hex(16)}"
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _no_follow_flags() | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
            return fd, name
        except FileExistsError:
            continue
        except OSError as exc:
            raise ValueError("Unable to create a private temporary manager file.") from exc
    raise RuntimeError("Unable to reserve a private temporary manager file.")


def _unlink_at_if_exists(parent_fd: int, name: str) -> None:
    info = _stat_at(parent_fd, name)
    if info is None:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        os.rmdir(name, dir_fd=parent_fd)
    else:
        os.unlink(name, dir_fd=parent_fd)


def _write_private_text_atomically(path: Path, content: str) -> None:
    parent_fd, name = _open_parent_directory_fd(path, create_parent=True, private_parent=True)
    temp_fd = None
    temp_name = None
    try:
        _ensure_regular_or_missing_at(parent_fd, name)
        temp_fd, temp_name = _new_temporary_file_at(parent_fd, name)
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            temp_fd = None
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None:
            _unlink_at_if_exists(parent_fd, temp_name)
        os.close(parent_fd)


def _copy_private_file_atomically(
    source: Path,
    target: Path,
    *,
    private_parent: bool = True,
) -> None:
    source_fd = _open_regular_no_follow(source, os.O_RDONLY)
    target_parent_fd, target_name = _open_parent_directory_fd(
        target,
        create_parent=True,
        private_parent=private_parent,
    )
    temp_fd = None
    temp_name = None
    try:
        _ensure_regular_or_missing_at(target_parent_fd, target_name)
        temp_fd, temp_name = _new_temporary_file_at(target_parent_fd, target_name)
        with os.fdopen(source_fd, "rb") as src, os.fdopen(temp_fd, "wb") as dst:
            source_fd = None
            temp_fd = None
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temp_name, target_name, src_dir_fd=target_parent_fd, dst_dir_fd=target_parent_fd)
        temp_name = None
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None:
            _unlink_at_if_exists(target_parent_fd, temp_name)
        os.close(target_parent_fd)


def ensure_layout(paths: ManagerPaths) -> None:
    _ensure_private_directory(paths.root)
    _ensure_private_child_directory(paths.root, paths.accounts_dir)
    _ensure_private_child_directory(paths.root, paths.runtime_dir)
    state_file = _assert_regular_file_or_missing(paths.state_file)
    if _lstat(state_file) is None:
        save_state(
            paths,
            {
                "active": None,
                "accounts": {},
                "live_dir": None,
                "switch_mode": DEFAULT_SWITCH_MODE,
                "switch_policy": _default_switch_policy(),
                "switch_runtime": _default_switch_runtime(),
                "switch_history": [],
            },
        )
    else:
        os.chmod(state_file, 0o600)


@contextmanager
def manager_lock(paths: ManagerPaths):
    lock_root = str(_absolute_path(paths.root))
    held_roots = _MANAGER_LOCK_ROOTS.get()
    if lock_root in held_roots:
        yield
        return

    ensure_layout(paths)
    fd = _open_regular_no_follow(paths.lock_file, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        lock_token = _MANAGER_LOCK_ROOTS.set((*held_roots, lock_root))
        try:
            f.seek(0)
            f.truncate()
            f.write(str(os.getpid()))
            f.flush()
            yield
        finally:
            _MANAGER_LOCK_ROOTS.reset(lock_token)
            try:
                f.seek(0)
                f.truncate()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def load_state(paths: ManagerPaths) -> dict:
    ensure_layout(paths)
    try:
        data = json.loads(_read_private_text(paths.state_file))
    except UnicodeDecodeError as exc:
        raise ValueError("Manager state file is unreadable.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Manager state file is invalid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Manager state file must be a JSON object.")
    _validate_state_schema(data)
    data.setdefault("active", None)
    data.setdefault("accounts", {})
    data.setdefault("live_dir", None)
    data["switch_mode"] = _normalize_switch_mode(data.get("switch_mode"))
    data["switch_policy"] = _normalize_switch_policy(data.get("switch_policy"))
    data["switch_runtime"] = _normalize_switch_runtime(data.get("switch_runtime"))
    data["switch_history"] = _normalize_switch_history(data.get("switch_history"))
    return data


def _coerce_state_integer(value: object) -> int:
    if isinstance(value, bool) or value is None or not isinstance(value, (str, int, float)):
        raise ValueError("Manager state file has invalid schema.")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Manager state file has invalid schema.") from None
    if isinstance(value, float) and (not math.isfinite(value) or value != result):
        raise ValueError("Manager state file has invalid schema.")
    return result


def _validate_state_schema(data: dict) -> None:
    accounts = data.get("accounts", {})
    if not isinstance(accounts, dict):
        raise ValueError("Manager state file has invalid schema.")
    for name, meta in accounts.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            raise ValueError("Manager state file has invalid schema.")
        try:
            normalize_account_storage_name(name)
        except (TypeError, ValueError):
            raise ValueError("Manager state file has invalid schema.") from None
        for key in ("fail_count", "refresh_fail_count", "refresh_policy_seconds"):
            if key in meta:
                _coerce_state_integer(meta[key])
        for key in ("cooldown_until", "created_at", "last_live_check_at", "next_live_check_at"):
            if key in meta and meta[key] is not None and not isinstance(meta[key], str):
                raise ValueError("Manager state file has invalid schema.")

    active = data.get("active")
    if active is not None and not isinstance(active, str):
        raise ValueError("Manager state file has invalid schema.")
    live_dir = data.get("live_dir")
    if live_dir is not None and not isinstance(live_dir, str):
        raise ValueError("Manager state file has invalid schema.")

    history = data.get("switch_history", [])
    if not isinstance(history, list):
        raise ValueError("Manager state file has invalid schema.")
    for item in history:
        if not isinstance(item, dict):
            raise ValueError("Manager state file has invalid schema.")
        if "cooldown_minutes" in item:
            _coerce_state_integer(item["cooldown_minutes"])


def save_state(paths: ManagerPaths, state: dict) -> None:
    _write_private_text_atomically(paths.state_file, json.dumps(state, indent=2, sort_keys=True))


def _normalize_switch_mode(value: object) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in VALID_SWITCH_MODES:
            return normalized
    return DEFAULT_SWITCH_MODE


def get_switch_mode(state: dict) -> str:
    return _normalize_switch_mode(state.get("switch_mode"))


def _default_switch_policy() -> dict:
    return {
        "short_usage_threshold_percent": DEFAULT_SHORT_SWITCH_THRESHOLD_PERCENT,
        "refresh_failure_threshold": DEFAULT_REFRESH_FAILURE_SWITCH_THRESHOLD,
        "candidate_strategy": DEFAULT_CANDIDATE_STRATEGY,
    }


def _normalize_candidate_strategy(value: object) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in VALID_CANDIDATE_STRATEGIES:
            return normalized
    return DEFAULT_CANDIDATE_STRATEGY


def _normalize_switch_policy(raw: object) -> dict:
    defaults = _default_switch_policy()
    policy = dict(defaults)
    if isinstance(raw, dict):
        threshold = raw.get("short_usage_threshold_percent")
        try:
            if threshold is not None:
                threshold_value = float(threshold)
                if 0.0 <= threshold_value <= 100.0:
                    policy["short_usage_threshold_percent"] = threshold_value
        except (TypeError, ValueError):
            pass
        failure_threshold = raw.get("refresh_failure_threshold")
        try:
            if failure_threshold is not None:
                failure_value = int(failure_threshold)
                if failure_value >= 1:
                    policy["refresh_failure_threshold"] = failure_value
        except (TypeError, ValueError):
            pass
        policy["candidate_strategy"] = _normalize_candidate_strategy(raw.get("candidate_strategy"))
    return policy


def _state_switch_policy(state: dict) -> dict:
    return _normalize_switch_policy(state.get("switch_policy"))


def _default_proxy_config() -> dict:
    return {
        "enabled": False,
        "url": None,
        "label": None,
    }


def _safe_proxy_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or len(raw) > 512 or any(ord(char) < 32 for char in raw):
        return None
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}:
        return None
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname
    if host is None:
        return None
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def _safe_proxy_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    label = " ".join(value.strip().split())
    if not label or len(label) > 96:
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._@-]*", label):
        return None
    return label


def _normalize_proxy_config(raw: object) -> dict:
    proxy = _default_proxy_config()
    if isinstance(raw, dict):
        proxy["enabled"] = bool(raw.get("enabled", False))
        proxy["url"] = _safe_proxy_url(raw.get("url"))
        proxy["label"] = _safe_proxy_label(raw.get("label"))
    if not proxy["url"]:
        proxy["enabled"] = False
    return proxy


def _default_switch_runtime() -> dict:
    return {
        "status": "idle",
        "reason": None,
        "trigger": None,
        "request_id": None,
        "active": None,
        "previous_active": None,
        "last_started_at": None,
        "last_completed_at": None,
    }


def _normalize_switch_runtime(raw: object) -> dict:
    runtime = _default_switch_runtime()
    if isinstance(raw, dict):
        for key in runtime:
            runtime[key] = raw.get(key)
    status = str(runtime.get("status") or "idle").strip().lower()
    if status not in {"idle", "switching", "ready", "no_account"}:
        status = "idle"
    runtime["status"] = status
    for key in ("reason", "trigger", "request_id", "active", "previous_active", "last_started_at", "last_completed_at"):
        value = runtime.get(key)
        normalized = value if isinstance(value, str) or value is None else str(value)
        runtime[key] = _normalize_failure_reason(normalized) if key == "reason" and normalized is not None else normalized
    return runtime


def _mark_switch_runtime(
    state: dict,
    *,
    status: str,
    reason: str | None = None,
    trigger: str | None = None,
    request_id: str | None = None,
    active: str | None = None,
    previous_active: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> None:
    runtime = _normalize_switch_runtime(state.get("switch_runtime"))
    runtime["status"] = status
    runtime["reason"] = reason
    runtime["trigger"] = trigger
    runtime["request_id"] = request_id
    runtime["active"] = active
    runtime["previous_active"] = previous_active
    if started_at is not None:
        runtime["last_started_at"] = started_at
    if completed_at is not None:
        runtime["last_completed_at"] = completed_at
    state["switch_runtime"] = runtime


def _normalize_switch_history(raw: object) -> list[dict]:
    if not isinstance(raw, list):
        return []
    entries: list[dict] = []
    for item in raw[-DEFAULT_SWITCH_HISTORY_LIMIT:]:
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "at": item.get("at") if isinstance(item.get("at"), str) or item.get("at") is None else str(item.get("at")),
                "reason": _normalize_failure_reason(item.get("reason")) if item.get("reason") is not None else None,
                "trigger": item.get("trigger") if isinstance(item.get("trigger"), str) or item.get("trigger") is None else str(item.get("trigger")),
                "request_id": item.get("request_id") if isinstance(item.get("request_id"), str) or item.get("request_id") is None else str(item.get("request_id")),
                "previous_active": item.get("previous_active") if isinstance(item.get("previous_active"), str) or item.get("previous_active") is None else str(item.get("previous_active")),
                "active": item.get("active") if isinstance(item.get("active"), str) or item.get("active") is None else str(item.get("active")),
                "switched_to": item.get("switched_to") if isinstance(item.get("switched_to"), str) or item.get("switched_to") is None else str(item.get("switched_to")),
                "outcome": item.get("outcome") if isinstance(item.get("outcome"), str) or item.get("outcome") is None else str(item.get("outcome")),
                "cooldown_minutes": _coerce_state_integer(item.get("cooldown_minutes", 0) or 0),
            }
        )
    return entries


def _append_switch_history(
    state: dict,
    *,
    reason: str | None,
    trigger: str | None,
    request_id: str | None,
    previous_active: str | None,
    active: str | None,
    switched_to: str | None,
    outcome: str | None,
    cooldown_minutes: int,
    at: str | None = None,
) -> None:
    history = _normalize_switch_history(state.get("switch_history"))
    history.append(
        {
            "at": at or utc_now().isoformat(),
            "reason": reason,
            "trigger": trigger,
            "request_id": request_id,
            "previous_active": previous_active,
            "active": active,
            "switched_to": switched_to,
            "outcome": outcome,
            "cooldown_minutes": int(cooldown_minutes or 0),
        }
    )
    state["switch_history"] = history[-DEFAULT_SWITCH_HISTORY_LIMIT:]


def account_dir(paths: ManagerPaths, name: str) -> Path:
    return paths.accounts_dir / normalize_account_storage_name(name)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _new_private_child_name(parent_fd: int, prefix: str) -> str:
    for _ in range(32):
        name = f".{prefix}-{secrets.token_hex(16)}"
        if _stat_at(parent_fd, name) is None:
            return name
    raise RuntimeError("Unable to reserve an internal manager path.")


def _create_private_child_directory_at(parent_fd: int, prefix: str) -> str:
    for _ in range(32):
        name = _new_private_child_name(parent_fd, prefix)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        child_fd = _open_child_directory_fd(parent_fd, name, private=True)
        os.close(child_fd)
        return name
    raise RuntimeError("Unable to create an internal manager directory.")


def _remove_tree_at(parent_fd: int, name: str, *, expected: os.stat_result | None = None) -> None:
    info = _stat_at(parent_fd, name)
    if info is None:
        return
    if expected is not None and not _same_inode(info, expected):
        raise ValueError("Manager path changed during a protected operation.")
    if stat.S_ISLNK(info.st_mode) or stat.S_ISREG(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Unsupported manager path type.")
    child_fd = _open_child_directory_fd(parent_fd, name)
    try:
        child_info = os.fstat(child_fd)
        if not _same_inode(info, child_info):
            raise ValueError("Manager path changed during a protected operation.")
        for child_name in os.listdir(child_fd):
            _remove_tree_at(child_fd, child_name)
    finally:
        os.close(child_fd)
    latest = _stat_at(parent_fd, name)
    if latest is None:
        return
    if not _same_inode(info, latest):
        raise ValueError("Manager path changed during a protected operation.")
    os.rmdir(name, dir_fd=parent_fd)


def _make_private_staging_directory(parent: Path, prefix: str) -> Path:
    parent_fd = _open_directory_fd_no_follow(parent, create=True, private_final=True)
    try:
        name = _create_private_child_directory_at(parent_fd, prefix)
        return parent / name
    finally:
        os.close(parent_fd)


def _remove_private_tree(path: Path) -> None:
    parent_fd, name = _open_parent_directory_fd(path)
    try:
        _remove_tree_at(parent_fd, name)
    finally:
        os.close(parent_fd)


@contextmanager
def _private_session_home(scratch_root: Path | None, prefix: str):
    root = scratch_root or (Path.home() / ".local" / "state" / "agy-profile-linux-sessions")
    home = _make_private_staging_directory(root, prefix)
    try:
        yield home
    finally:
        _remove_private_tree(home)


def resolve_agy_binary(agy_binary: str | None = None) -> str:
    if agy_binary and agy_binary.strip():
        return agy_binary.strip()

    env_binary = os.getenv("AGY_BINARY", "").strip()
    if env_binary:
        return env_binary

    path_binary = shutil.which("agy")
    if path_binary:
        return path_binary

    install_sibling = Path(__file__).resolve().parents[3] / "agy"
    if install_sibling.is_file() and os.access(install_sibling, os.X_OK):
        return str(install_sibling)

    raise ValueError(
        "agy binary not found. Use --agy-binary, set AGY_BINARY, or put `agy` in PATH."
    )


def _regular_file_exists_no_follow(path: Path) -> bool:
    absolute = _absolute_path(path)
    parent_info = _lstat(absolute.parent)
    if parent_info is None:
        return False
    if stat.S_ISLNK(parent_info.st_mode):
        raise ValueError(f"Unsafe symlink path: {absolute.parent}")
    if not stat.S_ISDIR(parent_info.st_mode):
        return False
    parent_fd, name = _open_parent_directory_fd(absolute)
    try:
        info = _stat_at(parent_fd, name)
        if info is None:
            return False
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"Unsafe symlink path: {_absolute_path(path)}")
        return stat.S_ISREG(info.st_mode)
    finally:
        os.close(parent_fd)


def _unlink_file_no_follow(path: Path, *, private_parent: bool = True) -> None:
    parent_fd, name = _open_parent_directory_fd(
        path,
        create_parent=True,
        private_parent=private_parent,
    )
    try:
        info = _stat_at(parent_fd, name)
        if info is None:
            return
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            raise ValueError("Expected managed file, not directory.")
        os.unlink(name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _ensure_directory_no_follow(path: Path) -> None:
    fd = _open_directory_fd_no_follow(path, create=True, private_final=False)
    os.close(fd)


def _copy_managed_profile_files(
    source: Path,
    target: Path,
    *,
    preserve_target_directory_modes: bool = False,
) -> None:
    if preserve_target_directory_modes:
        _ensure_directory_no_follow(target)
    else:
        _ensure_private_directory(target)
    for name in MANAGED_PROFILE_FILES:
        src = source / name
        dst = target / name
        if preserve_target_directory_modes:
            _ensure_directory_no_follow(dst.parent)
        else:
            _ensure_private_child_directory(target, dst.parent)
        if _regular_file_exists_no_follow(src):
            _copy_private_file_atomically(
                src,
                dst,
                private_parent=not preserve_target_directory_modes,
            )
        else:
            _unlink_file_no_follow(dst, private_parent=not preserve_target_directory_modes)


def _remove_managed_profile_files(target: Path) -> None:
    _ensure_private_directory(target)
    for name in MANAGED_PROFILE_FILES:
        _unlink_file_no_follow(target / name)


def _copy_account_profile(
    source_dir: Path,
    target_home: Path,
    *,
    preserve_target_directory_modes: bool = False,
) -> None:
    source_absolute = _absolute_path(source_dir)
    target_profile = target_home / ".gemini"
    source_parent_fd, source_name = _open_parent_directory_fd(source_absolute)
    try:
        source_info = _stat_at(source_parent_fd, source_name)
    finally:
        os.close(source_parent_fd)
    if source_info is None:
        _remove_managed_profile_files(target_profile)
        return
    if stat.S_ISLNK(source_info.st_mode):
        raise ValueError(f"Unsafe symlink path: {source_absolute}")
    if not stat.S_ISDIR(source_info.st_mode):
        raise ValueError(f"Expected profile directory: {source_absolute}")
    profile_source = _resolve_profile_source(source_absolute)
    _copy_managed_profile_files(
        profile_source,
        target_profile,
        preserve_target_directory_modes=preserve_target_directory_modes,
    )


def _resolve_profile_source(source_dir: Path) -> Path:
    source_dir = _absolute_path(source_dir)
    _assert_real_directory(source_dir)
    gemini_dir = source_dir / ".gemini"
    gemini_info = _lstat(gemini_dir)
    if gemini_info is not None and stat.S_ISLNK(gemini_info.st_mode):
        raise ValueError(f"Unsafe symlink path: {gemini_dir}")
    if gemini_info is not None and stat.S_ISDIR(gemini_info.st_mode):
        return gemini_dir
    return source_dir


def _resolve_home_source(source_dir: Path) -> Path:
    source_dir = _absolute_path(source_dir)
    _assert_real_directory(source_dir)
    gemini_dir = source_dir / ".gemini"
    gemini_info = _lstat(gemini_dir)
    if gemini_info is not None and stat.S_ISLNK(gemini_info.st_mode):
        raise ValueError(f"Unsafe symlink path: {gemini_dir}")
    if gemini_info is not None and stat.S_ISDIR(gemini_info.st_mode):
        return source_dir
    if source_dir.name == ".gemini":
        return source_dir.parent
    return source_dir


def _running_agy_pids(live_home: Path | None = None) -> list[int]:
    """Return same-user ``agy`` PIDs whose HOME matches ``live_home``."""
    pids: list[int] = []
    expected_home = str(_absolute_path(live_home)) if live_home is not None else None
    current_uid = os.getuid()
    try:
        entries = os.scandir("/proc")
    except OSError:
        return pids
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            proc_path = Path(entry.path)
            try:
                if os.stat(proc_path).st_uid != current_uid:
                    continue
                with open(proc_path / "comm", encoding="utf-8") as handle:
                    process_name = handle.read().strip()
                if process_name != "agy":
                    continue
                if expected_home is not None:
                    with open(proc_path / "environ", "rb") as handle:
                        environment = handle.read()
                    home = next(
                        (item[5:].decode("utf-8", "surrogateescape") for item in environment.split(b"\0") if item.startswith(b"HOME=")),
                        None,
                    )
                    if home != expected_home:
                        continue
            except (FileNotFoundError, PermissionError, OSError, UnicodeError):
                continue
            pids.append(pid)
    return pids


def close_live_agy(
    *,
    live_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> int:
    """Gracefully stop matching live-home agy processes; never SIGKILL."""
    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise ValueError("Close timeout must be between 0 and 60 seconds.")
    expected_home = _absolute_path(live_home or Path.home())
    pids = _running_agy_pids(expected_home)
    for pid in pids:
        if pid not in _running_agy_pids(expected_home):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            raise ValueError("Unable to request agy shutdown safely.") from exc
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        remaining = set(_running_agy_pids(expected_home)) & set(pids)
        if not remaining:
            return len(pids)
        time.sleep(0.1)
    raise ValueError("agy did not close within the timeout. Close it manually before switching.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _default_usage_window() -> dict:
    return {
        "status": "unknown",
        "value": None,
        "reset_at": None,
    }


def _default_usage_windows() -> dict:
    return {name: _default_usage_window() for name in USAGE_WINDOW_NAMES}


def _normalize_usage_windows(meta: dict) -> dict:
    raw_windows = meta.get("usage_windows")
    windows = _default_usage_windows()
    if isinstance(raw_windows, dict):
        for name in USAGE_WINDOW_NAMES:
            raw = raw_windows.get(name)
            if not isinstance(raw, dict):
                continue
            windows[name] = {
                "status": raw.get("status", "unknown") or "unknown",
                "value": raw.get("value"),
                "reset_at": raw.get("reset_at"),
            }

    short_window = windows["short"]
    if short_window.get("value") is None and meta.get("usage_value") is not None:
        short_window["value"] = meta.get("usage_value")
    if short_window.get("status") == "unknown" and meta.get("usage_status") is not None:
        short_window["status"] = meta.get("usage_status") or "unknown"
    if short_window.get("reset_at") is None and meta.get("reset_at") is not None:
        short_window["reset_at"] = meta.get("reset_at")
    return windows


def _sync_legacy_usage_fields(meta: dict) -> None:
    windows = _normalize_usage_windows(meta)
    meta["usage_windows"] = windows
    short_window = windows["short"]
    meta["usage_status"] = short_window.get("status", "unknown")
    meta["usage_value"] = short_window.get("value")
    meta["reset_at"] = short_window.get("reset_at")


def _normalize_timestamp(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError(f"Invalid timestamp value: {value}")
    return parsed.astimezone(timezone.utc).isoformat()


def _validate_live_dir(path: Path) -> Path:
    absolute = _assert_no_symlink_components(path)
    info = _lstat(absolute)
    if info is not None and not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"Expected live directory: {absolute}")
    return absolute


def _read_json_if_exists(path: Path) -> dict | list | None:
    absolute = _assert_regular_file_or_missing(path)
    if _lstat(absolute) is None:
        return None
    try:
        return json.loads(_read_private_text(absolute))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None


def _read_text_if_exists(path: Path) -> str | None:
    absolute = _assert_regular_file_or_missing(path)
    if _lstat(absolute) is None:
        return None
    try:
        value = _read_private_text(absolute).strip()
    except (UnicodeDecodeError, OSError):
        return None
    return value or None


def _oauth_token_path(home_root: Path) -> Path:
    return home_root / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"


def _project_id_path(home_root: Path) -> Path:
    return home_root / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt"


def _load_antigravity_token_state(home_root: Path) -> dict:
    path = _oauth_token_path(home_root)
    data = _read_json_if_exists(path)
    if not isinstance(data, dict):
        raise ValueError(f"Antigravity token file not found or invalid: {path}")
    token = data.get("token")
    if not isinstance(token, dict):
        raise ValueError(f"Antigravity token payload missing token object: {path}")
    return data


def _extract_access_token(home_root: Path) -> str:
    data = _load_antigravity_token_state(home_root)
    token = data.get("token")
    access_token = token.get("access_token") if isinstance(token, dict) else None
    if not isinstance(access_token, str) or not access_token.strip():
        raise ValueError("Antigravity access token is missing.")
    return access_token.strip()


def _has_refresh_token(home_root: Path) -> bool:
    data = _load_antigravity_token_state(home_root)
    token = data.get("token")
    refresh_token = token.get("refresh_token") if isinstance(token, dict) else None
    return isinstance(refresh_token, str) and bool(refresh_token.strip())


def _token_expiry_due(home_root: Path, skew_seconds: int = 120) -> bool:
    data = _load_antigravity_token_state(home_root)
    token = data.get("token")
    expiry_raw = token.get("expiry") if isinstance(token, dict) else None
    if not isinstance(expiry_raw, str) or not expiry_raw.strip():
        return False
    expiry = parse_timestamp(expiry_raw.strip().replace("Z", "+00:00"))
    if expiry is None:
        return False
    return expiry <= utc_now() + timedelta(seconds=skew_seconds)


def _persist_project_id(home_root: Path, project_id: str | None) -> None:
    if not project_id:
        return
    path = _project_id_path(home_root)
    profile_root = home_root / ".gemini"
    _ensure_private_child_directory(profile_root, path.parent)
    _write_private_text_atomically(path, project_id.strip() + "\n")


def _extract_project_id(load_response: dict, home_root: Path) -> str | None:
    project = load_response.get("cloudaicompanionProject")
    if isinstance(project, str) and project.strip():
        _persist_project_id(home_root, project.strip())
        return project.strip()
    if isinstance(project, dict):
        project_id = project.get("id")
        if isinstance(project_id, str) and project_id.strip():
            _persist_project_id(home_root, project_id.strip())
            return project_id.strip()
    cached = _read_text_if_exists(_project_id_path(home_root))
    return cached.strip() if isinstance(cached, str) and cached.strip() else None


def _cloudcode_request(access_token: str, path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        CODE_ASSIST_BASE_URL + path,
        data=body,
        headers={
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json",
            "User-Agent": CODE_ASSIST_USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"Unexpected Cloud Code response type for {path}")
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise PermissionError("Cloud Code authentication failed.") from exc
        raise ValueError(f"Cloud Code request failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError):
        raise ValueError("Cloud Code request failed due to a network error.") from None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        raise ValueError("Cloud Code returned an invalid response.") from None


def _google_userinfo_request(access_token: str) -> dict:
    req = urllib.request.Request(
        GOOGLE_USERINFO_URL,
        headers={
            "Authorization": "Bearer " + access_token,
            "User-Agent": CODE_ASSIST_USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Unexpected Google userinfo response type.")
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise PermissionError("Google userinfo authentication failed.") from exc
        raise ValueError(f"Google userinfo request failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError):
        raise ValueError("Google userinfo request failed due to a network error.") from None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        raise ValueError("Google userinfo returned an invalid response.") from None


def _run_agy_warmup(home_root: Path, agy_binary: str | None, timeout_seconds: int) -> None:
    raise ValueError(
        "Automatic agy warmup is disabled for safety. Complete an interactive login to refresh credentials."
    )


def _parse_summary_bucket(bucket: dict) -> dict:
    remaining = bucket.get("remainingFraction")
    reset_raw = bucket.get("resetTime")
    reset_at = None
    if isinstance(reset_raw, str):
        reset_at = _normalize_timestamp(reset_raw.replace("Z", "+00:00"))
    return {
        "status": "known" if isinstance(remaining, (int, float)) or reset_at else "unknown",
        "value": round(float(remaining) * 100, 2) if isinstance(remaining, (int, float)) else None,
        "reset_at": reset_at,
    }


def _select_quota_summary_group(summary_response: dict) -> dict | None:
    groups = summary_response.get("groups")
    if not isinstance(groups, list):
        return None
    normalized = [group for group in groups if isinstance(group, dict)]
    if not normalized:
        return None
    for group in normalized:
        display_name = group.get("displayName")
        if isinstance(display_name, str) and "gemini" in display_name.lower():
            return group
    return normalized[0]


def _parse_quota_windows_from_summary(summary_response: dict) -> tuple[dict, dict, int]:
    group = _select_quota_summary_group(summary_response)
    if not isinstance(group, dict):
        return _default_usage_window(), _default_usage_window(), 0
    buckets = group.get("buckets")
    if not isinstance(buckets, list):
        return _default_usage_window(), _default_usage_window(), 0

    short_window = _default_usage_window()
    weekly_window = _default_usage_window()
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        window_name = bucket.get("window")
        if window_name == "5h":
            short_window = _parse_summary_bucket(bucket)
        elif window_name == "weekly":
            weekly_window = _parse_summary_bucket(bucket)
    return short_window, weekly_window, len(buckets)


def _resolve_usage_refresh_target(paths: ManagerPaths, state: dict, name: str | None) -> tuple[str, Path]:
    account_name = name or state.get("active")
    if not account_name:
        raise ValueError("No active account is set.")
    if account_name not in state["accounts"]:
        raise ValueError(f"Account not found: {account_name}")
    if name is None:
        if state.get("live_dir"):
            raise ValueError(LIVE_DIR_SYNC_DISABLED_MESSAGE)
        return account_name, paths.runtime_dir
    return account_name, account_dir(paths, account_name)


def _run_agy_models_command(
    runtime_home: Path,
    agy_binary: str | None = None,
    timeout_seconds: int = 30,
) -> list[dict]:
    resolved_binary = resolve_agy_binary(agy_binary)
    env = os.environ.copy()
    env["HOME"] = str(runtime_home)
    env["PATH"] = env.get("PATH", "/bin:/usr/bin:/usr/local/bin")
    try:
        proc = subprocess.run(
            [resolved_binary, "models"],
            cwd=runtime_home,
            env=env,
            capture_output=True,
            text=True,
            timeout=max(10, timeout_seconds),
            check=False,
        )
    except UnicodeDecodeError:
        raise ValueError("agy models command returned invalid text output.") from None
    except subprocess.TimeoutExpired:
        raise ValueError("agy models command timed out.") from None
    except OSError:
        raise ValueError("Unable to execute agy models command.") from None
    output = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    if proc.returncode != 0:
        raise ValueError(
            f"agy models failed with exit code {proc.returncode}. "
            "Check the selected profile or complete an interactive login."
        )
    models: list[dict] = []
    for line in output.splitlines():
        parsed = _parse_model_label(line)
        if parsed:
            models.append(parsed)
    if not models:
        raise ValueError("agy models returned no usable model entries.")
    return models


def _account_due_for_refresh(meta: dict, now: datetime | None = None) -> bool:
    current = now or utc_now()
    if not isinstance(meta, dict):
        return False
    if not meta.get("enabled", True):
        return False
    status = meta.get("status") or "standby"
    if status in {"disabled", "cooldown"}:
        return False
    next_check = parse_timestamp(meta.get("next_live_check_at"))
    if next_check is not None:
        return next_check <= current
    policy = int(meta.get("refresh_policy_seconds", DEFAULT_REFRESH_POLICY_SECONDS) or DEFAULT_REFRESH_POLICY_SECONDS)
    if policy <= 0:
        return False
    last_check = parse_timestamp(meta.get("last_live_check_at"))
    if last_check is None:
        return True
    return last_check + timedelta(seconds=policy) <= current


def _eligible_switch_candidates(state: dict, exclude: str | None = None) -> list[str]:
    return [
        name
        for name, meta in sorted(state["accounts"].items())
        if name != exclude
        and meta.get("enabled", True)
        and meta.get("status") != "cooldown"
    ]


def _is_short_window_exhausted(meta: dict, now: datetime | None = None, *, threshold_percent: float = DEFAULT_SHORT_SWITCH_THRESHOLD_PERCENT) -> bool:
    current = now or utc_now()
    windows = _normalize_usage_windows(meta)
    short = windows.get("short", {})
    if short.get("status") != "known":
        return False
    value = _coerce_usage_value(short.get("value"))
    if value is None or value > threshold_percent:
        return False
    reset_at = parse_timestamp(short.get("reset_at"))
    if reset_at is not None and reset_at <= current:
        return False
    return True


def _cooldown_minutes_from_short_window(meta: dict, now: datetime | None = None) -> int:
    current = now or utc_now()
    windows = _normalize_usage_windows(meta)
    short = windows.get("short", {})
    reset_at = parse_timestamp(short.get("reset_at"))
    if reset_at is None or reset_at <= current:
        return 60
    delta_seconds = max(60.0, (reset_at - current).total_seconds())
    return max(1, int(math.ceil(delta_seconds / 60.0)))


def _refresh_failure_threshold_reached(meta: dict, threshold: int = DEFAULT_REFRESH_FAILURE_SWITCH_THRESHOLD) -> bool:
    return int(meta.get("refresh_fail_count", 0) or 0) >= threshold


def _coerce_usage_value(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None
    return None


def _candidate_usage_value(meta: dict, window_name: str) -> float | None:
    windows = _normalize_usage_windows(meta)
    window = windows.get(window_name, {})
    if not isinstance(window, dict):
        return None
    return _coerce_usage_value(window.get("value"))


def _candidate_health_priority(health: str) -> int:
    order = {
        "healthy": 0,
        "ready": 1,
        "stale": 2,
        "refresh_failed": 3,
        "auth_expired": 4,
        "auth_missing": 5,
        "cooldown": 6,
        "disabled": 7,
    }
    return order.get(health, 8)


def _best_switch_candidate(paths: ManagerPaths, state: dict, *, exclude: str | None = None) -> str | None:
    policy = _state_switch_policy(state)
    strategy = policy["candidate_strategy"]
    threshold_percent = float(policy["short_usage_threshold_percent"])
    candidates = _eligible_switch_candidates(state, exclude=exclude)
    if not candidates:
        return None

    ranked: list[tuple[tuple[object, ...], str]] = []
    for name in candidates:
        meta = state["accounts"].get(name)
        if not isinstance(meta, dict):
            continue
        health = _derive_health_status(paths, name, meta)
        if health in {"auth_missing", "auth_expired", "disabled", "cooldown"}:
            continue

        short_value = _candidate_usage_value(meta, "short")
        weekly_value = _candidate_usage_value(meta, "weekly")
        short_known = short_value is not None
        short_low = short_known and short_value <= threshold_percent
        weekly_known = weekly_value is not None

        if strategy == "highest-short":
            score = (
                0 if short_known else 1,
                -(short_value if short_value is not None else -1.0),
                _candidate_health_priority(health),
                int(meta.get("refresh_fail_count", 0) or 0),
                int(meta.get("fail_count", 0) or 0),
                str(meta.get("created_at") or ""),
                name.lower(),
            )
        elif strategy == "round-robin":
            score = (
                _candidate_health_priority(health),
                0 if short_known and not short_low else 1,
                str(meta.get("created_at") or ""),
                name.lower(),
            )
        else:
            score = (
                _candidate_health_priority(health),
                0 if short_known and not short_low else 1,
                0 if short_known else 1,
                -(short_value if short_value is not None else -1.0),
                0 if weekly_known else 1,
                -(weekly_value if weekly_value is not None else -1.0),
                int(meta.get("refresh_fail_count", 0) or 0),
                int(meta.get("fail_count", 0) or 0),
                str(meta.get("created_at") or ""),
                name.lower(),
            )
        ranked.append((score, name))

    if not ranked:
        return candidates[0]

    ranked.sort(key=lambda item: item[0])
    return ranked[0][1]


def pick_due_refresh_account(paths: ManagerPaths) -> str | None:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        now = utc_now()
        active_name = state.get("active")
        if active_name:
            active_meta = state["accounts"].get(active_name)
            if isinstance(active_meta, dict) and _account_due_for_refresh(active_meta, now):
                return active_name
        for name, meta in sorted(state["accounts"].items()):
            if name == active_name:
                continue
            if _account_due_for_refresh(meta, now):
                return name
    return None


def ensure_active_account(paths: ManagerPaths, *, force: bool = False) -> EnsureActiveResult:
    snapshot = get_status_snapshot(paths)
    switch_mode = snapshot.get("switch_mode", DEFAULT_SWITCH_MODE)
    switch_policy = snapshot.get("switch_policy") or _default_switch_policy()
    active_name = snapshot.get("active")
    accounts = snapshot.get("accounts", {})
    now = utc_now()

    if switch_mode != "auto" and not force:
        return EnsureActiveResult(
            triggered=False,
            switch_mode=switch_mode,
            previous_active=active_name,
            active=active_name,
            switched_to=None,
            reason=None,
            cooldown_minutes=0,
        )

    if not active_name:
        with manager_lock(paths):
            state = sync_state_from_disk(paths, load_state(paths))
            switched_to = _best_switch_candidate(paths, state)
            if switched_to:
                _activate_profile_transactionally(paths, state, switched_to)
                state["active"] = switched_to
                state = sync_state_from_disk(paths, state)
                save_state(paths, state)
        if not switched_to:
            return EnsureActiveResult(
                triggered=False,
                switch_mode=switch_mode,
                previous_active=None,
                active=None,
                switched_to=None,
                reason="no_active_account",
                cooldown_minutes=0,
            )
        return EnsureActiveResult(
            triggered=True,
            switch_mode=switch_mode,
            previous_active=None,
            active=switched_to,
            switched_to=switched_to,
            reason="no_active_account",
            cooldown_minutes=0,
        )

    active_meta = accounts.get(active_name)
    if not isinstance(active_meta, dict):
        with manager_lock(paths):
            state = sync_state_from_disk(paths, load_state(paths))
            switched_to = _best_switch_candidate(paths, state, exclude=active_name)
            if switched_to:
                _activate_profile_transactionally(paths, state, switched_to)
                state["active"] = switched_to
                state = sync_state_from_disk(paths, state)
                save_state(paths, state)
        if not switched_to:
            return EnsureActiveResult(
                triggered=False,
                switch_mode=switch_mode,
                previous_active=active_name,
                active=None,
                switched_to=None,
                reason="active_missing",
                cooldown_minutes=0,
            )
        return EnsureActiveResult(
            triggered=True,
            switch_mode=switch_mode,
            previous_active=active_name,
            active=switched_to,
            switched_to=switched_to,
            reason="active_missing",
            cooldown_minutes=0,
        )

    reason = None
    cooldown_minutes = 0
    health = active_meta.get("health_status")
    if health in {"auth_missing", "auth_expired"}:
        reason = health
        cooldown_minutes = 60
    elif _is_short_window_exhausted(
        active_meta,
        now,
        threshold_percent=float(switch_policy.get("short_usage_threshold_percent", DEFAULT_SHORT_SWITCH_THRESHOLD_PERCENT)),
    ):
        reason = "quota_exhausted"
        cooldown_minutes = _cooldown_minutes_from_short_window(active_meta, now)
    elif _refresh_failure_threshold_reached(
        active_meta,
        threshold=int(switch_policy.get("refresh_failure_threshold", DEFAULT_REFRESH_FAILURE_SWITCH_THRESHOLD)),
    ):
        reason = "refresh_failed"
        cooldown_minutes = 10

    if reason is None:
        return EnsureActiveResult(
            triggered=False,
            switch_mode=switch_mode,
            previous_active=active_name,
            active=active_name,
            switched_to=None,
            reason=None,
            cooldown_minutes=0,
        )

    result = rotate_after_failure(
        paths,
        reason=reason,
        cooldown_minutes=cooldown_minutes,
        force_switch=True,
    )
    return EnsureActiveResult(
        triggered=bool(result.switched_to or result.previous_active),
        switch_mode=switch_mode,
        previous_active=result.previous_active,
        active=result.active,
        switched_to=result.switched_to,
        reason=reason,
        cooldown_minutes=cooldown_minutes,
    )


def refresh_due_account(
    paths: ManagerPaths,
    *,
    agy_binary: str | None = None,
    warmup_timeout_seconds: int = 45,
) -> UsageRefreshResult | None:
    ensure_active_account(paths)
    target = pick_due_refresh_account(paths)
    if target is None:
        return None
    return refresh_account_usage(
        paths,
        target,
        agy_binary=agy_binary,
        warmup_timeout_seconds=warmup_timeout_seconds,
    )


def list_models(
    paths: ManagerPaths,
    name: str | None = None,
    *,
    agy_binary: str | None = None,
    timeout_seconds: int = 30,
) -> dict:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        account_name, source_home = _resolve_usage_refresh_target(paths, state, name)
        if not profile_has_login_artifacts(_resolve_profile_source(source_home)):
            fallback_home = account_dir(paths, account_name)
            if name is None and profile_has_login_artifacts(_resolve_profile_source(fallback_home)):
                source_home = fallback_home
            else:
                raise ValueError(f"Profile source is missing required auth files: {_resolve_profile_source(source_home)}")

        # `agy models` may write caches. Use a private per-call session so model
        # discovery cannot mutate a saved account, the manager runtime, or a real CLI home.
        model_home = _make_private_staging_directory(paths.root, "models")
        try:
            _copy_account_profile(source_home, model_home)
            models = _run_agy_models_command(model_home, agy_binary=agy_binary, timeout_seconds=timeout_seconds)
        finally:
            _remove_private_tree(model_home)
        return {
            "account": account_name,
            "source_home": str(source_home),
            "models": models,
            "count": len(models),
        }


def _persist_refresh_failure(paths: ManagerPaths, account_name: str, _error: str) -> None:
    failed_at = utc_now()
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(account_name)
        if meta is None:
            return
        meta["health_status"] = "refresh_failed"
        meta["last_live_check_error"] = "Usage refresh failed. Retry later or complete an interactive login."
        meta["refresh_fail_count"] = int(meta.get("refresh_fail_count", 0) or 0) + 1
        meta["next_live_check_at"] = _normalize_timestamp(failed_at + timedelta(minutes=5))
        save_state(paths, state)


def refresh_account_usage(
    paths: ManagerPaths,
    name: str | None = None,
    *,
    agy_binary: str | None = None,
    warmup_timeout_seconds: int = 45,
) -> UsageRefreshResult:
    with manager_lock(paths):
        return _refresh_account_usage_unlocked(
            paths,
            name,
            agy_binary=agy_binary,
            warmup_timeout_seconds=warmup_timeout_seconds,
        )


def _refresh_account_usage_unlocked(
    paths: ManagerPaths,
    name: str | None = None,
    *,
    agy_binary: str | None = None,
    warmup_timeout_seconds: int = 45,
) -> UsageRefreshResult:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        account_name, source_home = _resolve_usage_refresh_target(paths, state, name)
    try:
        try:
            access_token = _extract_access_token(source_home)
        except ValueError as exc:
            raise ValueError(
                "Account credentials are invalid. Complete an interactive login before checking usage."
            ) from exc
        if _token_expiry_due(source_home):
            raise ValueError(
                "Account credentials are expired. Complete an interactive login before checking usage."
            )

        try:
            load_response = _cloudcode_request(
                access_token,
                CODE_ASSIST_LOAD_PATH,
                {
                    "metadata": {
                        "ideType": "ANTIGRAVITY",
                        "platform": "PLATFORM_UNSPECIFIED",
                        "pluginType": "GEMINI",
                    }
                },
            )
        except PermissionError as exc:
            raise ValueError(
                "Cloud Code rejected the stored credentials. Complete an interactive login before checking usage."
            ) from exc

        project_id = _extract_project_id(load_response, source_home)
        if not project_id:
            raise ValueError("Cloud Code project id is unavailable.")

        quota_response = _cloudcode_request(access_token, CODE_ASSIST_QUOTA_SUMMARY_PATH, {"project": project_id})
        short_window, weekly_window, bucket_count = _parse_quota_windows_from_summary(quota_response)
        plan_info = load_response.get("planInfo")
        plan_type = plan_info.get("planType") if isinstance(plan_info, dict) else None
        monthly = plan_info.get("monthlyPromptCredits") if isinstance(plan_info, dict) else None
        available = load_response.get("availablePromptCredits")

        result = UsageRefreshResult(
            account=account_name,
            source_home=str(source_home),
            project_id=project_id,
            plan_type=plan_type if isinstance(plan_type, str) else None,
            prompt_credits_available=available if isinstance(available, (int, float)) else None,
            prompt_credits_monthly=monthly if isinstance(monthly, (int, float)) else None,
            short_usage_status=short_window.get("status", "unknown"),
            short_usage_value=short_window.get("value"),
            short_reset_at=short_window.get("reset_at"),
            weekly_usage_status=weekly_window.get("status", "unknown"),
            weekly_usage_value=weekly_window.get("value"),
            weekly_reset_at=weekly_window.get("reset_at"),
            bucket_count=bucket_count,
        )

        refreshed_at = utc_now()
        if source_home != account_dir(paths, account_name):
            target_dir = account_dir(paths, account_name)
            if target_dir.exists():
                source_profile = _resolve_profile_source(source_home)
                target_profile = target_dir / ".gemini"
                _copy_managed_profile_files(source_profile, target_profile)
        refreshed_identity = detect_profile_identity(account_dir(paths, account_name))
        if not refreshed_identity.get("account_name") and isinstance(access_token, str) and access_token.strip():
            try:
                live_identity = _best_effort_live_identity(access_token.strip())
                if live_identity:
                    refreshed_identity = live_identity
            except (PermissionError, ValueError):
                pass
        with manager_lock(paths):
            state = sync_state_from_disk(paths, load_state(paths))
            meta = state["accounts"].get(account_name)
            if meta is None:
                raise ValueError(f"Account not found: {account_name}")
            windows = _normalize_usage_windows(meta)
            windows["short"]["status"] = result.short_usage_status
            windows["short"]["value"] = result.short_usage_value
            windows["short"]["reset_at"] = result.short_reset_at
            windows["weekly"]["status"] = result.weekly_usage_status
            windows["weekly"]["value"] = result.weekly_usage_value
            windows["weekly"]["reset_at"] = result.weekly_reset_at
            meta["usage_windows"] = windows
            meta["health_status"] = "healthy"
            meta["last_live_check_at"] = _normalize_timestamp(refreshed_at)
            meta["last_live_check_error"] = None
            meta["refresh_fail_count"] = 0
            policy_seconds = int(meta.get("refresh_policy_seconds", DEFAULT_REFRESH_POLICY_SECONDS) or DEFAULT_REFRESH_POLICY_SECONDS)
            meta["next_live_check_at"] = _normalize_timestamp(refreshed_at + timedelta(seconds=policy_seconds))
            meta["identity"] = refreshed_identity
            _sync_legacy_usage_fields(meta)
            save_state(paths, state)

        ensure_active_account(paths)
        return result
    except Exception as exc:
        _persist_refresh_failure(paths, account_name, str(exc))
        try:
            ensure_active_account(paths)
        except ValueError:
            pass
        raise


def _decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _identity_from_payload(payload: dict, source: str) -> dict | None:
    if not isinstance(payload, dict):
        return None
    email = payload.get("email")
    name = payload.get("name")
    subject = payload.get("sub") or payload.get("id")
    account_name = None
    if isinstance(email, str) and email.strip():
        account_name = email.strip()
    elif isinstance(name, str) and name.strip():
        account_name = name.strip()
    elif isinstance(subject, str) and subject.strip():
        account_name = subject.strip()
    if not account_name:
        return None
    identity = {
        "account_name": account_name,
        "source": source,
    }
    if isinstance(email, str) and email.strip():
        identity["email"] = email.strip()
    if isinstance(name, str) and name.strip():
        identity["display_name"] = name.strip()
    if isinstance(subject, str) and subject.strip():
        identity["subject"] = subject.strip()
    return identity


def _identity_from_google_accounts(google_accounts: dict | list) -> dict | None:
    if isinstance(google_accounts, dict):
        active = google_accounts.get("active")
        if isinstance(active, str) and active.strip():
            identity = {
                "account_name": active.strip(),
                "source": "google_accounts.json.active",
            }
            if "@" in active:
                identity["email"] = active.strip()
            return identity
        accounts = google_accounts.get("accounts") or google_accounts.get("old")
        if isinstance(accounts, list):
            for entry in accounts:
                if isinstance(entry, str) and entry.strip() and "@" in entry:
                    return {
                        "account_name": entry.strip(),
                        "email": entry.strip(),
                        "source": "google_accounts.json.accounts",
                    }
                if isinstance(entry, dict):
                    identity = _identity_from_payload(entry, "google_accounts.json.accounts")
                    if identity:
                        return identity
    elif isinstance(google_accounts, list):
        for entry in google_accounts:
            if isinstance(entry, dict):
                identity = _identity_from_payload(entry, "google_accounts.json")
                if identity:
                    return identity
            elif isinstance(entry, str) and entry.strip() and "@" in entry:
                return {
                    "account_name": entry.strip(),
                    "email": entry.strip(),
                    "source": "google_accounts.json",
                }
    return None


def _identity_from_oauth_creds(oauth_creds: dict) -> dict | None:
    if not isinstance(oauth_creds, dict):
        return None
    direct_identity = _identity_from_payload(oauth_creds, "oauth_creds.json")
    if direct_identity:
        return direct_identity
    for key in ("user", "user_info", "userinfo", "profile"):
        nested = oauth_creds.get(key)
        if isinstance(nested, dict):
            nested_identity = _identity_from_payload(nested, f"oauth_creds.json.{key}")
            if nested_identity:
                return nested_identity
    for token_key in ("id_token", "token", "access_token"):
        token_value = oauth_creds.get(token_key)
        if isinstance(token_value, str) and token_value.strip() and token_value.count(".") >= 2:
            payload = _decode_jwt_payload(token_value.strip())
            identity = _identity_from_payload(payload or {}, f"oauth_creds.json.{token_key}")
            if identity:
                return identity
    return None


def _identity_from_antigravity_token(token_state: dict) -> dict | None:
    if not isinstance(token_state, dict):
        return None
    direct_identity = _identity_from_payload(token_state, "antigravity-oauth-token")
    if direct_identity:
        return direct_identity
    token = token_state.get("token")
    if isinstance(token, dict):
        token_identity = _identity_from_payload(token, "antigravity-oauth-token.token")
        if token_identity:
            return token_identity
        for token_key in ("id_token", "access_token"):
            token_value = token.get(token_key)
            if isinstance(token_value, str) and token_value.strip() and token_value.count(".") >= 2:
                payload = _decode_jwt_payload(token_value.strip())
                identity = _identity_from_payload(payload or {}, f"antigravity-oauth-token.token.{token_key}")
                if identity:
                    return identity
    return None


def _iter_antigravity_log_texts(home_root: Path) -> list[tuple[str, str]]:
    base_dir = home_root / ".gemini" / "antigravity-cli"
    base_fd = _open_directory_fd_no_follow(base_dir)
    try:
        entries: list[tuple[int, str, str]] = []
        cli_text = _read_regular_text_at(base_fd, "cli.log")
        if cli_text is not None:
            info = _stat_at(base_fd, "cli.log")
            entries.append((info.st_mtime_ns if info else 0, "cli.log", cli_text))

        log_info = _stat_at(base_fd, "log")
        if log_info is None:
            return [(name, text) for _mtime, name, text in entries]
        if stat.S_ISLNK(log_info.st_mode):
            raise ValueError("Unsafe symlink manager directory.")
        if not stat.S_ISDIR(log_info.st_mode):
            raise ValueError("Expected log directory.")
        log_fd = _open_child_directory_fd(base_fd, "log")
        try:
            for name in os.listdir(log_fd):
                info = _stat_at(log_fd, name)
                if info is None:
                    continue
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError("Unsafe symlink manager file.")
                if not stat.S_ISREG(info.st_mode):
                    continue
                text = _read_regular_text_at(log_fd, name)
                if text is not None:
                    entries.append((info.st_mtime_ns, f"log/{name}", text))
        finally:
            os.close(log_fd)
        entries.sort(key=lambda item: item[0], reverse=True)
        return [(name, text) for _mtime, name, text in entries]
    finally:
        os.close(base_fd)


def _identity_from_antigravity_logs(source_dir: Path) -> dict | None:
    home_root = _resolve_home_source(source_dir)
    for name, text in _iter_antigravity_log_texts(home_root):
        for line in reversed(text.splitlines()):
            match = APPLY_AUTH_EMAIL_PATTERN.search(line)
            if match:
                email = match.group(1).strip()
                if email:
                    return {
                        "account_name": email,
                        "email": email,
                        "source": f"antigravity-cli.log:{name}",
                    }
            if "Cache(userInfo)" in line:
                match = EMAIL_PATTERN.search(line)
                if match:
                    email = match.group(0).strip()
                    if email:
                        return {
                            "account_name": email,
                            "email": email,
                            "source": f"antigravity-cli.log:{name}",
                        }
    return None


def _best_effort_live_identity(access_token: str) -> dict | None:
    userinfo = _google_userinfo_request(access_token)
    return _identity_from_payload(userinfo, "google_userinfo")


def _best_effort_saved_profile_identity(source_dir: Path) -> dict:
    identity = detect_profile_identity(source_dir)
    if identity.get("account_name"):
        return identity
    log_identity = _identity_from_antigravity_logs(source_dir)
    if log_identity:
        return log_identity
    # Importing or switching a profile must stay local.  A caller can explicitly
    # request a live identity refresh instead of sending a saved token by default.
    return identity


def detect_profile_identity(source_dir: Path) -> dict:
    profile_source = _resolve_profile_source(source_dir)
    google_accounts = _read_json_if_exists(profile_source / "google_accounts.json")
    if google_accounts is not None:
        identity = _identity_from_google_accounts(google_accounts)
        if identity:
            return identity

    google_account_id = _read_text_if_exists(profile_source / "google_account_id")
    if google_account_id:
        identity = {
            "account_name": google_account_id,
            "source": "google_account_id",
        }
        if "@" in google_account_id:
            identity["email"] = google_account_id
        return identity

    oauth_creds = _read_json_if_exists(profile_source / "oauth_creds.json")
    if isinstance(oauth_creds, dict):
        identity = _identity_from_oauth_creds(oauth_creds)
        if identity:
            return identity

    try:
        token_state = _load_antigravity_token_state(_resolve_home_source(source_dir))
    except ValueError:
        token_state = None
    if isinstance(token_state, dict):
        identity = _identity_from_antigravity_token(token_state)
        if identity:
            return identity
    identity = _identity_from_antigravity_logs(source_dir)
    if identity:
        return identity

    return {
        "account_name": None,
        "source": "unavailable",
    }


def normalize_account_storage_name(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError("Account name cannot be empty.")
    if not ACCOUNT_NAME_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Account name may contain only letters, digits, spaces, '.', '_', '-', and '@', "
            "and must start with a letter or digit."
        )
    return cleaned


def next_available_account_name(paths: ManagerPaths, base_name: str) -> str:
    candidate = base_name
    suffix = 2
    while account_dir(paths, candidate).exists():
        candidate = f"{base_name}.{suffix}"
        suffix += 1
    return candidate


def _update_account_identity(state: dict, name: str, identity: dict) -> None:
    meta = state["accounts"].setdefault(name, {})
    meta["identity"] = identity


def refresh_account_identity(paths: ManagerPaths, name: str) -> dict:
    identity = _best_effort_saved_profile_identity(account_dir(paths, name))
    if not identity.get("account_name"):
        try:
            probe = probe_profile_identity_via_usage(
                account_dir(paths, name),
                scratch_root=paths.root,
            )
            if probe.get("account_name"):
                identity = probe
        except (ValueError, subprocess.TimeoutExpired):
            pass
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        if name not in state["accounts"]:
            raise ValueError(f"Account not found: {name}")
        _update_account_identity(state, name, identity)
        save_state(paths, state)
    return identity


def get_account_identity(paths: ManagerPaths, name: str | None = None) -> tuple[str, dict]:
    state = sync_state_from_disk(paths, load_state(paths))
    resolved_name = name or state.get("active")
    if not resolved_name:
        raise ValueError("No active account is set.")
    if resolved_name not in state["accounts"]:
        raise ValueError(f"Account not found: {resolved_name}")
    cached = state["accounts"][resolved_name].get("identity")
    if isinstance(cached, dict) and cached.get("account_name"):
        return resolved_name, cached
    return resolved_name, refresh_account_identity(paths, resolved_name)


def probe_profile_identity_via_usage(
    source_dir: Path,
    agy_binary: str | None = None,
    timeout_seconds: int = 30,
    live_dir: Path | None = None,
    *,
    scratch_root: Path | None = None,
) -> dict:
    del live_dir
    resolved_binary = resolve_agy_binary(agy_binary)
    source_home = _resolve_home_source(source_dir)
    profile_source = _resolve_profile_source(source_dir)
    if not profile_has_login_artifacts(profile_source):
        raise ValueError(f"Profile source is missing required auth files: {profile_source}")

    # Never temporarily swap credentials into an existing CLI home. Manager callers
    # supply a private scratch root; public callers still get a secure 0700 temp home.
    with _private_session_home(scratch_root, "usage-probe") as runtime_home:
        _copy_account_profile(source_home, runtime_home)

        env = os.environ.copy()
        env["HOME"] = str(runtime_home)
        env["PATH"] = env.get("PATH", "/bin:/usr/bin:/usr/local/bin")

        try:
            proc = subprocess.run(
                [resolved_binary, "-p", "/usage"],
                cwd=runtime_home,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except UnicodeDecodeError:
            raise ValueError("agy usage probe returned invalid text output.") from None
        except subprocess.TimeoutExpired:
            raise ValueError("agy usage probe timed out.") from None
        except OSError:
            raise ValueError("Unable to execute agy usage probe.") from None
        output = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
        if proc.returncode != 0:
            raise ValueError(
                f"agy usage probe failed with exit code {proc.returncode}. "
                "Check the selected profile or complete an interactive login."
            )

        match = EMAIL_PATTERN.search(output)
        if match:
            return {
                "account_name": match.group(0),
                "source": "agy:/usage",
            }
        return {
            "account_name": None,
            "source": "agy:/usage",
        }


def resolve_login_profile_identity(
    source_dir: Path,
    agy_binary: str | None = None,
    live_dir: Path | None = None,
    *,
    scratch_root: Path | None = None,
) -> dict:
    identity = _best_effort_saved_profile_identity(source_dir)
    if identity.get("account_name"):
        return identity
    try:
        probe = probe_profile_identity_via_usage(
            source_dir,
            agy_binary=agy_binary,
            timeout_seconds=30,
            live_dir=live_dir,
            scratch_root=scratch_root,
        )
    except (ValueError, subprocess.TimeoutExpired):
        return identity
    if probe.get("account_name"):
        return probe
    return identity


def _has_login_artifact_files(profile_dir: Path) -> bool:
    return any(
        all(_regular_file_exists_no_follow(profile_dir / name) for name in artifact_set)
        for artifact_set in LOGIN_ARTIFACT_SETS
    )


def profile_has_login_artifacts(profile_dir: Path) -> bool:
    if not _has_login_artifact_files(profile_dir):
        return False
    try:
        _extract_access_token(_resolve_home_source(profile_dir))
    except ValueError:
        return False
    return True


def _derive_health_status(paths: ManagerPaths, name: str, meta: dict) -> str:
    if not meta.get("enabled", True):
        return "disabled"
    cooldown_until = parse_timestamp(meta.get("cooldown_until"))
    if cooldown_until and cooldown_until > utc_now():
        return "cooldown"
    account_path = account_dir(paths, name)
    profile_source = _resolve_profile_source(account_path)
    if not profile_has_login_artifacts(profile_source):
        return "auth_missing"
    try:
        source_home = _resolve_home_source(account_path)
        _extract_access_token(source_home)
        if _token_expiry_due(source_home):
            if not _has_refresh_token(source_home):
                return "auth_expired"
            return "stale"
    except ValueError:
        pass
    if meta.get("last_live_check_error"):
        return "refresh_failed"
    next_live_check_at = parse_timestamp(meta.get("next_live_check_at"))
    if next_live_check_at and next_live_check_at <= utc_now():
        return "stale"
    if meta.get("last_live_check_at"):
        return "healthy"
    return "ready"


def verify_account(paths: ManagerPaths, name: str, meta: dict) -> dict:
    account_path = account_dir(paths, name)
    profile_source = _resolve_profile_source(account_path)
    source_home = _resolve_home_source(account_path)
    enabled = bool(meta.get("enabled", True))
    cooldown_until = parse_timestamp(meta.get("cooldown_until"))
    has_artifacts = profile_has_login_artifacts(profile_source)
    has_access_token = False
    has_refresh_token = False
    access_token_expired = False

    if has_artifacts:
        try:
            _extract_access_token(source_home)
            has_access_token = True
        except ValueError:
            has_access_token = False
        try:
            has_refresh_token = _has_refresh_token(source_home)
        except ValueError:
            has_refresh_token = False
        try:
            access_token_expired = _token_expiry_due(source_home)
        except ValueError:
            access_token_expired = False

    health_status = _derive_health_status(paths, name, meta)
    problem_status = "ok"
    recommended_action = "none"
    summary = "Ready for use."

    if not enabled:
        problem_status = "disabled"
        recommended_action = "enable"
        summary = "Account is disabled."
    elif cooldown_until and cooldown_until > utc_now():
        problem_status = "cooldown"
        recommended_action = "wait"
        summary = f"Account is in cooldown until {cooldown_until.isoformat()}."
    elif not has_artifacts:
        problem_status = "missing_auth"
        recommended_action = "relogin"
        summary = "Managed auth files are missing."
    elif health_status == "auth_expired" or (has_access_token and access_token_expired and not has_refresh_token):
        problem_status = "logged_out"
        recommended_action = "relogin"
        summary = "Access token is expired and no refresh token is available."
    elif meta.get("last_live_check_error"):
        problem_status = "refresh_failed"
        recommended_action = "refresh"
        summary = f"Last live check failed: {meta.get('last_live_check_error')}"
    elif health_status == "stale":
        problem_status = "stale"
        recommended_action = "refresh"
        summary = "Cached live status is stale; refresh is recommended."

    return {
        "name": name,
        "problem_status": problem_status,
        "recommended_action": recommended_action,
        "summary": summary,
        "health_status": health_status,
        "enabled": enabled,
        "has_login_artifacts": has_artifacts,
        "has_access_token": has_access_token,
        "has_refresh_token": has_refresh_token,
        "access_token_expired": access_token_expired,
        "cooldown_until": meta.get("cooldown_until"),
        "last_live_check_error": meta.get("last_live_check_error"),
        "proxy": _normalize_proxy_config(meta.get("proxy")),
    }


def verify_accounts(paths: ManagerPaths) -> dict:
    state = sync_state_from_disk(paths, load_state(paths))
    accounts = {}
    for name, meta in sorted(state["accounts"].items()):
        accounts[name] = verify_account(paths, name, meta)
    return {
        "active": state.get("active"),
        "switch_mode": get_switch_mode(state),
        "accounts": accounts,
    }


def sync_state_from_disk(paths: ManagerPaths, state: dict) -> dict:
    accounts_fd = _open_directory_fd_no_follow(paths.accounts_dir, create=True, private_final=True)
    try:
        disk_account_stats: dict[str, os.stat_result] = {}
        for name in os.listdir(accounts_fd):
            info = _stat_at(accounts_fd, name)
            if info is None:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"Unsafe symlink path: {paths.accounts_dir / name}")
            if not name.startswith(".") and stat.S_ISDIR(info.st_mode):
                disk_account_stats[name] = info
    finally:
        os.close(accounts_fd)
    disk_accounts = set(disk_account_stats)
    tracked = state["accounts"]

    for name in sorted(disk_accounts):
        try:
            created_at = datetime.fromtimestamp(disk_account_stats[name].st_mtime, timezone.utc).isoformat()
        except OSError:
            created_at = utc_now().isoformat()
        tracked.setdefault(
            name,
            {
                "enabled": True,
                "status": "standby",
                "last_error": None,
                "cooldown_until": None,
                "fail_count": 0,
                "created_at": created_at,
                "usage_windows": _default_usage_windows(),
                "usage_status": "unknown",
                "usage_value": None,
                "reset_at": None,
                "health_status": "unknown",
                "last_live_check_at": None,
                "last_live_check_error": None,
                "refresh_fail_count": 0,
                "next_live_check_at": None,
                "refresh_policy_seconds": DEFAULT_REFRESH_POLICY_SECONDS,
                "proxy": _default_proxy_config(),
            },
        )
        meta = tracked[name]
        if meta.get("last_error") is not None:
            meta["last_error"] = _normalize_failure_reason(meta.get("last_error"))
        if meta.get("last_live_check_error") is not None:
            meta["last_live_check_error"] = "Usage refresh failed. Retry later or complete an interactive login."
        meta.setdefault("created_at", created_at)
        meta.setdefault("usage_windows", _default_usage_windows())
        meta.setdefault("health_status", "unknown")
        meta.setdefault("last_live_check_at", None)
        meta.setdefault("last_live_check_error", None)
        meta.setdefault("refresh_fail_count", 0)
        meta.setdefault("next_live_check_at", None)
        meta.setdefault("refresh_policy_seconds", DEFAULT_REFRESH_POLICY_SECONDS)
        meta["proxy"] = _normalize_proxy_config(meta.get("proxy"))
        _sync_legacy_usage_fields(meta)
    for name in list(tracked):
        if name not in disk_accounts:
            tracked.pop(name, None)
            if state.get("active") == name:
                state["active"] = None

    active = state.get("active")
    for name, meta in tracked.items():
        cooldown_until = parse_timestamp(meta.get("cooldown_until"))
        in_cooldown = bool(cooldown_until and cooldown_until > utc_now())
        if name == active:
            meta["status"] = "active"
        elif not meta.get("enabled", True):
            meta["status"] = "disabled"
        elif in_cooldown:
            meta["status"] = "cooldown"
        else:
            meta["status"] = "standby"
    return state


def save_account_profile(
    paths: ManagerPaths,
    name: str,
    source_dir: Path,
    overwrite: bool = False,
    *,
    activate_if_empty: bool = True,
) -> None:
    name = normalize_account_storage_name(name)
    source_dir = _absolute_path(source_dir)

    with manager_lock(paths):
        _assert_real_directory(source_dir)
        home_source = _resolve_home_source(source_dir)
        profile_source = _resolve_profile_source(source_dir)
        _assert_real_directory(profile_source)
        if not profile_has_login_artifacts(profile_source):
            raise ValueError(f"Profile source is missing required auth files: {profile_source}")
        state = sync_state_from_disk(paths, load_state(paths))
        accounts_fd = _open_directory_fd_no_follow(paths.accounts_dir, create=True, private_final=True)
        try:
            target_info = _stat_at(accounts_fd, name)
            if target_info is not None and stat.S_ISLNK(target_info.st_mode):
                raise ValueError("Unsafe symlink account entry.")
            if target_info is not None and not stat.S_ISDIR(target_info.st_mode):
                raise ValueError("Expected account directory.")
            if target_info is not None and not overwrite:
                raise ValueError(f"Account already exists: {name}")

            stage_name = _create_private_child_directory_at(accounts_fd, "stage-profile")
            stage = paths.accounts_dir / stage_name
            backup_name = None
            runtime_snapshot = None
            target_moved = False
            stage_promoted = False
            state_before = json.loads(json.dumps(state))
            try:
                _copy_account_profile(home_source, stage)
                identity = _best_effort_saved_profile_identity(stage)

                current_target = _stat_at(accounts_fd, name)
                if target_info is None:
                    if current_target is not None:
                        raise ValueError("Account entry changed during save.")
                elif current_target is None or not _same_inode(target_info, current_target):
                    raise ValueError("Account entry changed during save.")
                if target_info is not None:
                    backup_name = _new_private_child_name(accounts_fd, "backup-profile")
                    os.replace(name, backup_name, src_dir_fd=accounts_fd, dst_dir_fd=accounts_fd)
                    target_moved = True
                os.replace(stage_name, name, src_dir_fd=accounts_fd, dst_dir_fd=accounts_fd)
                stage_promoted = True

                previous_meta = state["accounts"].get(name, {})
                state["accounts"][name] = {
                    "enabled": previous_meta.get("enabled", True),
                    "status": previous_meta.get("status", "standby"),
                    "last_error": None if overwrite else previous_meta.get("last_error"),
                    "cooldown_until": None if overwrite else previous_meta.get("cooldown_until"),
                    "fail_count": 0 if overwrite else previous_meta.get("fail_count", 0),
                    "refresh_fail_count": 0 if overwrite else previous_meta.get("refresh_fail_count", 0),
                    "created_at": previous_meta.get("created_at") or utc_now().isoformat(),
                    "usage_windows": _normalize_usage_windows(previous_meta),
                    "usage_status": previous_meta.get("usage_status", "unknown"),
                    "usage_value": previous_meta.get("usage_value"),
                    "reset_at": previous_meta.get("reset_at"),
                    "health_status": previous_meta.get("health_status", "unknown"),
                    "last_live_check_at": previous_meta.get("last_live_check_at"),
                    "last_live_check_error": previous_meta.get("last_live_check_error"),
                    "next_live_check_at": previous_meta.get("next_live_check_at"),
                    "refresh_policy_seconds": int(previous_meta.get("refresh_policy_seconds", DEFAULT_REFRESH_POLICY_SECONDS) or DEFAULT_REFRESH_POLICY_SECONDS),
                    "identity": identity,
                    "proxy": _normalize_proxy_config(previous_meta.get("proxy")),
                }
                _sync_legacy_usage_fields(state["accounts"][name])

                if (overwrite and state_before.get("active") == name) or (
                    activate_if_empty and not state_before.get("active")
                ):
                    runtime_snapshot = _make_private_staging_directory(paths.root, ".stage-runtime-")
                    _copy_account_profile(paths.runtime_dir, runtime_snapshot)
                    _copy_active_runtime(paths, name)
                    if activate_if_empty and not state_before.get("active"):
                        state["active"] = name
                state = sync_state_from_disk(paths, state)
                save_state(paths, state)
            except Exception:
                if runtime_snapshot is not None:
                    _copy_account_profile(runtime_snapshot, paths.runtime_dir)
                if stage_promoted:
                    _remove_tree_at(accounts_fd, name)
                if target_moved and backup_name is not None and _stat_at(accounts_fd, backup_name) is not None:
                    os.replace(backup_name, name, src_dir_fd=accounts_fd, dst_dir_fd=accounts_fd)
                raise
            finally:
                _remove_tree_at(accounts_fd, stage_name)
                if runtime_snapshot is not None:
                    _remove_private_tree(runtime_snapshot)
                if backup_name is not None:
                    _remove_tree_at(accounts_fd, backup_name)
        finally:
            os.close(accounts_fd)


def add_account(paths: ManagerPaths, name: str, source_dir: Path) -> None:
    save_account_profile(paths, name, source_dir, overwrite=False)


def import_current(paths: ManagerPaths, name: str, source_dir: Path | None = None) -> None:
    if source_dir is None:
        raise ValueError("An explicit source directory is required in this hardened build.")
    add_account(paths, name, source_dir)


def save_current_account(
    paths: ManagerPaths,
    name: str,
    *,
    live_home: Path | None = None,
    overwrite: bool = False,
) -> None:
    """Save the account currently present in the normal agy home."""
    live_home = _absolute_path(live_home or Path.home())
    save_account_profile(paths, name, live_home, overwrite=overwrite)


def _copy_active_runtime(paths: ManagerPaths, name: str) -> None:
    src = account_dir(paths, name)
    if _lstat(_absolute_path(src)) is None:
        raise ValueError(f"Account not found: {name}")
    _assert_real_directory(src)
    if not profile_has_login_artifacts(_resolve_profile_source(src)):
        raise ValueError(f"Account {name} is missing required auth files")

    _ensure_private_child_directory(paths.root, paths.runtime_dir)
    _copy_account_profile(src, paths.runtime_dir)


def _activate_profile_transactionally(paths: ManagerPaths, state: dict, name: str) -> None:
    if state.get("live_dir"):
        raise ValueError(LIVE_DIR_SYNC_DISABLED_MESSAGE)
    runtime_snapshot = _make_private_staging_directory(paths.root, "stage-runtime")
    try:
        _copy_account_profile(paths.runtime_dir, runtime_snapshot)
        try:
            _copy_active_runtime(paths, name)
        except Exception:
            _copy_account_profile(runtime_snapshot, paths.runtime_dir)
            raise
    finally:
        _remove_private_tree(runtime_snapshot)


def switch_account(paths: ManagerPaths, name: str) -> str:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        if not meta.get("enabled", True):
            raise ValueError(f"Account is disabled: {name}")
        cooldown_until = parse_timestamp(meta.get("cooldown_until"))
        if cooldown_until and cooldown_until > utc_now():
            raise ValueError(f"Account is in cooldown until {cooldown_until.isoformat()}: {name}")

        previous = state.get("active")
        _activate_profile_transactionally(paths, state, name)
        state["active"] = name
        state = sync_state_from_disk(paths, state)
        save_state(paths, state)
        return previous or ""


def switch_live_account(
    paths: ManagerPaths,
    name: str,
    *,
    live_home: Path | None = None,
    close_running: bool = False,
    close_timeout_seconds: float = 10.0,
) -> str:
    """Switch only account-bound files in the normal agy home.

    Shared ``.gemini`` data is left untouched. The live OAuth credential and
    account-bound project ID are changed together, with rollback if either the
    copy or state update fails.
    """
    live_home = _absolute_path(live_home or Path.home())
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        if not meta.get("enabled", True):
            raise ValueError(f"Account is disabled: {name}")
        cooldown_until = parse_timestamp(meta.get("cooldown_until"))
        if cooldown_until and cooldown_until > utc_now():
            raise ValueError(f"Account is in cooldown until {cooldown_until.isoformat()}: {name}")
        running = _running_agy_pids(live_home)
        if running:
            if not close_running:
                raise ValueError("agy is running. Close agy before switching accounts, or use --close.")
            close_live_agy(live_home=live_home, timeout_seconds=close_timeout_seconds)
        _assert_real_directory(live_home)

        previous = state.get("active")
        snapshot = _make_private_staging_directory(paths.root, ".stage-live-")
        try:
            _copy_account_profile(live_home, snapshot)
            try:
                _copy_account_profile(account_dir(paths, name), live_home, preserve_target_directory_modes=True)
                state["active"] = name
                state = sync_state_from_disk(paths, state)
                save_state(paths, state)
            except Exception:
                _copy_account_profile(snapshot, live_home, preserve_target_directory_modes=True)
                raise
        finally:
            _remove_private_tree(snapshot)
        return previous or ""


def switch_next(paths: ManagerPaths) -> str:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        candidates = _eligible_switch_candidates(state)
        if not candidates:
            raise ValueError("No enabled non-cooldown accounts available.")

        current = state.get("active")
        target = _best_switch_candidate(paths, state, exclude=current)
        if target is None and current in candidates and len(candidates) == 1:
            target = current
        if target is None:
            raise ValueError("No eligible standby account is available.")
        if len(candidates) == 1 and current == target:
            raise ValueError("Only one eligible account is available.")
        _activate_profile_transactionally(paths, state, target)
        state["active"] = target
        state = sync_state_from_disk(paths, state)
        save_state(paths, state)
        return target


def get_status_snapshot(paths: ManagerPaths) -> dict:
    state = sync_state_from_disk(paths, load_state(paths))
    snapshot_accounts = {}
    for name, meta in sorted(state["accounts"].items()):
        derived_health_status = _derive_health_status(paths, name, meta)
        snapshot_accounts[name] = {
            "enabled": bool(meta.get("enabled", True)),
            "status": meta.get("status", "standby"),
            "last_error": meta.get("last_error"),
            "cooldown_until": meta.get("cooldown_until"),
            "fail_count": int(meta.get("fail_count", 0) or 0),
            "refresh_fail_count": int(meta.get("refresh_fail_count", 0) or 0),
            "created_at": meta.get("created_at"),
            "usage_windows": _normalize_usage_windows(meta),
            "usage_status": meta.get("usage_status", "unknown"),
            "usage_value": meta.get("usage_value"),
            "reset_at": meta.get("reset_at"),
            "health_status": derived_health_status,
            "stored_health_status": meta.get("health_status", "unknown"),
            "last_live_check_at": meta.get("last_live_check_at"),
            "last_live_check_error": meta.get("last_live_check_error"),
            "next_live_check_at": meta.get("next_live_check_at"),
            "refresh_policy_seconds": int(meta.get("refresh_policy_seconds", DEFAULT_REFRESH_POLICY_SECONDS) or DEFAULT_REFRESH_POLICY_SECONDS),
            "identity": meta.get("identity") if isinstance(meta.get("identity"), dict) else None,
            "proxy": _normalize_proxy_config(meta.get("proxy")),
        }
    active_name = state.get("active")
    active_meta = state["accounts"].get(active_name) if active_name else None
    return {
        "root": str(paths.root),
        "runtime_dir": str(paths.runtime_dir),
        "lock_file": str(paths.lock_file),
        "live_dir": state.get("live_dir"),
        "active": active_name,
        "active_proxy": _normalize_proxy_config(active_meta.get("proxy")) if isinstance(active_meta, dict) else _default_proxy_config(),
        "switch_mode": get_switch_mode(state),
        "switch_policy": _state_switch_policy(state),
        "switch_runtime": _normalize_switch_runtime(state.get("switch_runtime")),
        "switch_history": _normalize_switch_history(state.get("switch_history")),
        "accounts": snapshot_accounts,
    }


def get_switch_policy(paths: ManagerPaths) -> dict:
    state = sync_state_from_disk(paths, load_state(paths))
    return dict(_state_switch_policy(state))


def get_account_proxy(paths: ManagerPaths, name: str | None = None) -> tuple[str, dict]:
    state = sync_state_from_disk(paths, load_state(paths))
    resolved_name = name or state.get("active")
    if not resolved_name:
        raise ValueError("No active account.")
    meta = state["accounts"].get(resolved_name)
    if meta is None:
        raise ValueError(f"Unknown account: {resolved_name}")
    return resolved_name, _normalize_proxy_config(meta.get("proxy"))


def list_account_proxies(paths: ManagerPaths) -> dict:
    state = sync_state_from_disk(paths, load_state(paths))
    accounts = {}
    for name, meta in sorted(state["accounts"].items()):
        accounts[name] = {
            "active": name == state.get("active"),
            "status": meta.get("status", "standby"),
            "enabled": bool(meta.get("enabled", True)),
            "proxy": _normalize_proxy_config(meta.get("proxy")),
        }
    return {
        "active": state.get("active"),
        "accounts": accounts,
    }


def set_account_proxy(
    paths: ManagerPaths,
    name: str,
    *,
    url: str,
    label: str | None = None,
    enabled: bool = True,
) -> dict:
    proxy_url = _safe_proxy_url(url)
    if proxy_url is None:
        raise ValueError(
            "Proxy URL must use http(s)/socks5 without credentials, path, query, or fragment."
        )
    proxy_label = _safe_proxy_label(label)
    if label is not None and proxy_label is None:
        raise ValueError("Proxy label contains unsupported characters.")
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Unknown account: {name}")
        meta["proxy"] = _normalize_proxy_config(
            {
                "enabled": enabled,
                "url": proxy_url,
                "label": proxy_label,
            }
        )
        save_state(paths, state)
        return dict(meta["proxy"])


def clear_account_proxy(paths: ManagerPaths, name: str) -> None:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Unknown account: {name}")
        meta["proxy"] = _default_proxy_config()
        save_state(paths, state)


def set_switch_mode(paths: ManagerPaths, mode: str) -> str:
    normalized = _normalize_switch_mode(mode)
    if normalized != mode.strip().lower():
        raise ValueError(f"Unsupported switch mode: {mode}")
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        state["switch_mode"] = normalized
        save_state(paths, state)
        return normalized


def update_switch_policy(
    paths: ManagerPaths,
    *,
    short_usage_threshold_percent: float | None = None,
    refresh_failure_threshold: int | None = None,
    candidate_strategy: str | None = None,
) -> dict:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        policy = _state_switch_policy(state)
        if short_usage_threshold_percent is not None:
            value = float(short_usage_threshold_percent)
            if value < 0.0 or value > 100.0:
                raise ValueError("short_usage_threshold_percent must be between 0 and 100.")
            policy["short_usage_threshold_percent"] = value
        if refresh_failure_threshold is not None:
            value = int(refresh_failure_threshold)
            if value < 1:
                raise ValueError("refresh_failure_threshold must be at least 1.")
            policy["refresh_failure_threshold"] = value
        if candidate_strategy is not None:
            normalized_strategy = _normalize_candidate_strategy(candidate_strategy)
            if normalized_strategy != candidate_strategy.strip().lower():
                raise ValueError(f"Unsupported candidate strategy: {candidate_strategy}")
            policy["candidate_strategy"] = normalized_strategy
        state["switch_policy"] = policy
        save_state(paths, state)
        return dict(policy)


def set_enabled(paths: ManagerPaths, name: str, enabled: bool) -> None:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        meta["enabled"] = enabled
        if not enabled and state.get("active") == name:
            state["active"] = None
        state = sync_state_from_disk(paths, state)
        save_state(paths, state)


def mark_bad(paths: ManagerPaths, name: str, reason: str, cooldown_minutes: int) -> None:
    reason = _normalize_failure_reason(reason)
    if cooldown_minutes < 0:
        raise ValueError("Cooldown minutes must be non-negative.")
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        meta["last_error"] = reason
        meta["fail_count"] = int(meta.get("fail_count", 0)) + 1
        if cooldown_minutes > 0:
            meta["cooldown_until"] = (utc_now() + timedelta(minutes=cooldown_minutes)).isoformat()
        else:
            meta["cooldown_until"] = None
        if state.get("active") == name:
            state["active"] = None
        state = sync_state_from_disk(paths, state)
        save_state(paths, state)


def clear_bad(paths: ManagerPaths, name: str) -> None:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        meta["last_error"] = None
        meta["cooldown_until"] = None
        meta["refresh_fail_count"] = 0
        meta["last_live_check_error"] = None
        state = sync_state_from_disk(paths, state)
        save_state(paths, state)


def update_account_runtime_metadata(
    paths: ManagerPaths,
    name: str,
    *,
    usage_status: str | None = None,
    usage_value: str | int | float | None = None,
    reset_at: datetime | str | None = None,
    short_usage_status: str | None = None,
    short_usage_value: str | int | float | None = None,
    short_reset_at: datetime | str | None = None,
    weekly_usage_status: str | None = None,
    weekly_usage_value: str | int | float | None = None,
    weekly_reset_at: datetime | str | None = None,
    health_status: str | None = None,
    last_live_check_at: datetime | str | None = None,
    last_live_check_error: str | None = None,
    next_live_check_at: datetime | str | None = None,
    refresh_policy_seconds: int | None = None,
) -> dict:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        meta = state["accounts"].get(name)
        if meta is None:
            raise ValueError(f"Account not found: {name}")
        windows = _normalize_usage_windows(meta)
        if usage_status is not None:
            windows["short"]["status"] = usage_status
        if usage_value is not None:
            windows["short"]["value"] = usage_value
        if reset_at is not None:
            windows["short"]["reset_at"] = _normalize_timestamp(reset_at)
        if short_usage_status is not None:
            windows["short"]["status"] = short_usage_status
        if short_usage_value is not None:
            windows["short"]["value"] = short_usage_value
        if short_reset_at is not None:
            windows["short"]["reset_at"] = _normalize_timestamp(short_reset_at)
        if weekly_usage_status is not None:
            windows["weekly"]["status"] = weekly_usage_status
        if weekly_usage_value is not None:
            windows["weekly"]["value"] = weekly_usage_value
        if weekly_reset_at is not None:
            windows["weekly"]["reset_at"] = _normalize_timestamp(weekly_reset_at)
        meta["usage_windows"] = windows
        _sync_legacy_usage_fields(meta)
        if health_status is not None:
            meta["health_status"] = health_status
        if last_live_check_at is not None:
            meta["last_live_check_at"] = _normalize_timestamp(last_live_check_at)
        if last_live_check_error is not None:
            meta["last_live_check_error"] = "Usage refresh failed. Retry later or complete an interactive login."
        if next_live_check_at is not None:
            meta["next_live_check_at"] = _normalize_timestamp(next_live_check_at)
        if refresh_policy_seconds is not None:
            if refresh_policy_seconds <= 0:
                raise ValueError("refresh_policy_seconds must be positive.")
            meta["refresh_policy_seconds"] = int(refresh_policy_seconds)
        save_state(paths, state)
        return get_status_snapshot(paths)["accounts"][name]


def set_live_dir(paths: ManagerPaths, live_dir: Path | None) -> None:
    if live_dir is not None:
        _validate_live_dir(live_dir)
        raise ValueError(LIVE_DIR_SYNC_DISABLED_MESSAGE)
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        state["live_dir"] = None
        save_state(paths, state)


def apply_active(paths: ManagerPaths) -> str:
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        active = state.get("active")
        if not active:
            raise ValueError("No active account is set.")
        _activate_profile_transactionally(paths, state, active)
        save_state(paths, state)
        return active


def run_active(
    paths: ManagerPaths,
    agy_binary: str | None = None,
    agy_args: list[str] | None = None,
) -> int:
    args = list(agy_args or [])
    if any(not isinstance(arg, str) for arg in args):
        raise ValueError("agy arguments must be strings.")
    resolved_binary = resolve_agy_binary(agy_binary)
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        active = state.get("active")
        if not active:
            raise ValueError("No active account is set.")
        source_home = account_dir(paths, active)
        if not profile_has_login_artifacts(_resolve_profile_source(source_home)):
            raise ValueError(f"Account {active} is missing required auth files")
        session_home = _make_private_staging_directory(paths.root, "run-session")
        try:
            _copy_account_profile(source_home, session_home)
            env = os.environ.copy()
            env["HOME"] = str(session_home)
            try:
                proc = subprocess.run(
                    [resolved_binary, *args],
                    cwd=session_home,
                    env=env,
                    check=False,
                    close_fds=True,
                )
            except OSError as exc:
                raise ValueError("Unable to start agy. Check that the configured binary is executable.") from exc
            return int(proc.returncode)
        finally:
            _remove_private_tree(session_home)


def rotate_after_failure(
    paths: ManagerPaths,
    reason: str,
    cooldown_minutes: int = 60,
    live_dir: Path | None = None,
    force_switch: bool = False,
    dedupe_seconds: int = DEFAULT_SWITCH_DEDUPE_SECONDS,
    trigger: str = "unknown",
    request_id: str | None = None,
) -> RotationResult:
    reason = _normalize_failure_reason(reason)
    if cooldown_minutes < 0:
        raise ValueError("Cooldown minutes must be non-negative.")
    if live_dir is not None:
        _validate_live_dir(live_dir)
        raise ValueError(LIVE_DIR_SYNC_DISABLED_MESSAGE)

    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        switch_mode = get_switch_mode(state)
        runtime = _normalize_switch_runtime(state.get("switch_runtime"))
        now = utc_now()
        now_iso = now.isoformat()

        last_completed_at = parse_timestamp(runtime.get("last_completed_at"))
        if (
            runtime.get("status") == "ready"
            and runtime.get("reason") == reason
            and last_completed_at is not None
            and (now - last_completed_at).total_seconds() <= dedupe_seconds
            and state.get("active")
        ):
            _mark_switch_runtime(
                state,
                status="ready",
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                active=state.get("active"),
                previous_active=runtime.get("previous_active"),
                started_at=runtime.get("last_started_at"),
                completed_at=runtime.get("last_completed_at"),
            )
            _append_switch_history(
                state,
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                previous_active=runtime.get("previous_active"),
                active=state.get("active"),
                switched_to=None,
                outcome="already_switched",
                cooldown_minutes=0,
                at=runtime.get("last_completed_at"),
            )
            save_state(paths, state)
            return RotationResult(
                previous_active=runtime.get("previous_active"),
                active=state.get("active"),
                switched_to=None,
                marked_bad=False,
                reason=reason,
                cooldown_minutes=0,
                outcome="already_switched",
            )

        previous = state.get("active")
        _mark_switch_runtime(
            state,
            status="switching",
            reason=reason,
            trigger=trigger,
            request_id=request_id,
            active=previous,
            previous_active=previous,
            started_at=now_iso,
            completed_at=None,
        )
        if not previous:
            _mark_switch_runtime(
                state,
                status="no_account",
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                active=None,
                previous_active=None,
                completed_at=utc_now().isoformat(),
            )
            _append_switch_history(
                state,
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                previous_active=None,
                active=None,
                switched_to=None,
                outcome="no_active",
                cooldown_minutes=cooldown_minutes,
            )
            save_state(paths, state)
            return RotationResult(
                previous_active=None,
                active=None,
                switched_to=None,
                marked_bad=False,
                reason=reason,
                cooldown_minutes=cooldown_minutes,
                outcome="no_active",
            )

        meta = state["accounts"].get(previous)
        if meta is None:
            state["active"] = None
            _mark_switch_runtime(
                state,
                status="no_account",
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                active=None,
                previous_active=previous,
                completed_at=utc_now().isoformat(),
            )
            _append_switch_history(
                state,
                reason=reason,
                trigger=trigger,
                request_id=request_id,
                previous_active=previous,
                active=None,
                switched_to=None,
                outcome="active_missing",
                cooldown_minutes=cooldown_minutes,
            )
            save_state(paths, state)
            return RotationResult(
                previous_active=previous,
                active=None,
                switched_to=None,
                marked_bad=False,
                reason=reason,
                cooldown_minutes=cooldown_minutes,
                outcome="active_missing",
            )

        meta["last_error"] = reason
        meta["fail_count"] = int(meta.get("fail_count", 0)) + 1
        if cooldown_minutes > 0:
            meta["cooldown_until"] = (utc_now() + timedelta(minutes=cooldown_minutes)).isoformat()
        else:
            meta["cooldown_until"] = None
        state["active"] = None
        state = sync_state_from_disk(paths, state)

        switched_to = None
        if force_switch or switch_mode == "auto":
            switched_to = _best_switch_candidate(paths, state, exclude=previous)
            if switched_to:
                _activate_profile_transactionally(paths, state, switched_to)
                state["active"] = switched_to
                state = sync_state_from_disk(paths, state)

        _mark_switch_runtime(
            state,
            status="ready" if state.get("active") else "no_account",
            reason=reason,
            trigger=trigger,
            request_id=request_id,
            active=state.get("active"),
            previous_active=previous,
            completed_at=utc_now().isoformat(),
        )
        _append_switch_history(
            state,
            reason=reason,
            trigger=trigger,
            request_id=request_id,
            previous_active=previous,
            active=state.get("active"),
            switched_to=switched_to,
            outcome="switched" if switched_to else "no_candidate",
            cooldown_minutes=cooldown_minutes,
        )
        save_state(paths, state)
        return RotationResult(
            previous_active=previous,
            active=state.get("active"),
            switched_to=switched_to,
            marked_bad=True,
            reason=reason,
            cooldown_minutes=cooldown_minutes,
            outcome="switched" if switched_to else "no_candidate",
        )


def login_account(
    paths: ManagerPaths,
    name: str,
    agy_binary: str | None,
    timeout_seconds: int = 600,
) -> str | None:
    storage_name = normalize_account_storage_name(name)
    if not os.isatty(sys.stdin.fileno()):
        raise ValueError("Interactive login requires a TTY.")

    resolved_binary = resolve_agy_binary(agy_binary)
    with manager_lock(paths):
        state = sync_state_from_disk(paths, load_state(paths))
        state["live_dir"] = None
        save_state(paths, state)

    with _private_session_home(paths.root, "login") as runtime_home:
        env = os.environ.copy()
        env["HOME"] = str(runtime_home)
        env["PATH"] = env.get("PATH", "/bin:/usr/bin:/usr/local/bin")
        try:
            proc = subprocess.Popen(
                [resolved_binary],
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
                cwd=runtime_home,
                env=env,
                close_fds=True,
            )
        except OSError as exc:
            raise ValueError("agy binary was not found or is not executable.") from exc

        start_time = time.time()
        print("Launching isolated agy login session.")
        print("Complete onboarding/login there, then exit agy to save the profile.")
        sys.stdout.flush()
        try:
            while True:
                if proc.poll() is not None:
                    break
                if time.time() - start_time > timeout_seconds:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    raise ValueError(f"Login timed out after {timeout_seconds} seconds.")
                time.sleep(0.2)
        except KeyboardInterrupt:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            raise

        profile_dir = runtime_home / ".gemini"
        if not profile_dir.is_dir() or not profile_has_login_artifacts(profile_dir):
            raise ValueError("agy login did not produce a usable auth profile.")

        overwrite = False
        if account_dir(paths, storage_name).exists():
            prompt = f"Account '{storage_name}' already exists. Overwrite it? [y/N]: "
            answer = input(prompt).strip().lower()
            if answer not in {"y", "yes"}:
                storage_name = next_available_account_name(paths, storage_name)
                print(f"saving-as: {storage_name}")
            else:
                overwrite = True

        # Login always saves a standby profile.  The user explicitly chooses when
        # to activate it, so a fresh login cannot silently replace the live account.
        save_account_profile(
            paths,
            storage_name,
            runtime_home,
            overwrite=overwrite,
            activate_if_empty=False,
        )
    return storage_name


def format_status(paths: ManagerPaths) -> str:
    state = sync_state_from_disk(paths, load_state(paths))
    save_state(paths, state)
    switch_runtime = _normalize_switch_runtime(state.get("switch_runtime"))
    switch_history = _normalize_switch_history(state.get("switch_history"))
    lines = [
        f"root: {paths.root}",
        f"runtime: {paths.runtime_dir}",
        f"lock: {paths.lock_file}",
        f"live_dir: {state.get('live_dir') or '-'}",
        f"active: {state.get('active') or '-'}",
        f"active_proxy: {_normalize_proxy_config(state['accounts'].get(state.get('active'), {}).get('proxy') if state.get('active') else None).get('label') or (_normalize_proxy_config(state['accounts'].get(state.get('active'), {}).get('proxy') if state.get('active') else None).get('url') or '-')}",
        f"switch_mode: {get_switch_mode(state)}",
        (
            "switch_runtime: "
            f"{switch_runtime.get('status') or 'idle'}"
            f" reason={switch_runtime.get('reason') or '-'}"
            f" trigger={switch_runtime.get('trigger') or '-'}"
            f" active={switch_runtime.get('active') or '-'}"
            f" previous={switch_runtime.get('previous_active') or '-'}"
        ),
        (
            "last_switch: "
            f"{(switch_history[-1].get('outcome') if switch_history else '-')}"
            f" reason={(switch_history[-1].get('reason') if switch_history else '-')}"
            f" trigger={(switch_history[-1].get('trigger') if switch_history else '-')}"
            f" at={(switch_history[-1].get('at') if switch_history else '-')}"
        ),
        "accounts:",
    ]
    for name, meta in sorted(state["accounts"].items()):
        flag = "enabled" if meta.get("enabled", True) else "disabled"
        extra = []
        identity = meta.get("identity")
        if isinstance(identity, dict) and identity.get("account_name"):
            extra.append(f"account_name={identity['account_name']}")
            if identity.get("source"):
                extra.append(f"identity_source={identity['source']}")
        if meta.get("cooldown_until"):
            extra.append(f"cooldown_until={meta['cooldown_until']}")
        if meta.get("fail_count"):
            extra.append(f"fail_count={meta['fail_count']}")
        if meta.get("refresh_fail_count"):
            extra.append(f"refresh_fail_count={meta['refresh_fail_count']}")
        if meta.get("last_error"):
            extra.append(f"last_error={meta['last_error']}")
        proxy = _normalize_proxy_config(meta.get("proxy"))
        if proxy.get("url"):
            extra.append(f"proxy_label={proxy.get('label') or '-'}")
            extra.append(f"proxy_enabled={proxy.get('enabled', False)}")
        suffix = f" [{' ; '.join(extra)}]" if extra else ""
        lines.append(f"  - {name}: {meta.get('status', 'standby')} ({flag}){suffix}")
    if not state["accounts"]:
        lines.append("  - none")
    return "\n".join(lines)
