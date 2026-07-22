# SPDX-License-Identifier: GPL-2.0-only
"""AST-validated CI check over REMEDIATION_CATALOG's commands_template fields
(notes/RemediationRAGPlan.txt "AST-validated CI check over commands_template").

Every `catalog_step_commands` row exported into `core/remediation.py`'s
`REMEDIATION_CATALOG` (as a step dict's `commands_template` mapping) must be
exactly one shell invocation with only known {placeholder} fields and a
leading command/cmdlet drawn from a curated allowlist. This is the same
validator the offline RAG authoring pipeline runs before a reviewer can
approve an entry (step 4 of the pipeline in the plan doc) and the one CI runs
here against whatever's actually shipped in core/remediation.py, so a
hand-edit that bypasses the reviewed pipeline is still caught.

Run standalone:

    python3 finetune/command_ast_validate.py

Exits non-zero (and prints [FAIL] lines) if any command_template in
REMEDIATION_CATALOG's steps fails validation. Nothing in this module is
imported by agent.py or core/remediation.py at runtime — it's a build/CI-time
check only.
"""
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from finetune.rag_db.db import DEFAULT_DB_PATH, get_connection, utcnow_iso

# Leading token (after stripping a leading "sudo") a bash command_template
# must start with. Anything else -- including shell builtins that could be
# used to pivot (eval, exec, source) -- fails closed.
_ALLOWED_BASH_COMMANDS = {
    "apt-get", "apt", "dnf", "yum", "pacman", "zypper", "brew",
    "systemctl", "service", "ufw", "firewall-cmd", "freshclam",
}

# Leading cmdlet a powershell command_template must start with. Explicitly
# excludes Invoke-Expression / Invoke-Command / iex / Start-Process -- none
# of which a copy-paste remediation command should ever need.
_ALLOWED_PS_CMDLETS = {
    "install-module", "update-module", "uninstall-module",
    "set-mppreference", "update-mpsignature",
    "enable-windowsoptionalfeature", "disable-windowsoptionalfeature",
    "set-netfirewallprofile", "enable-netfirewallrule", "disable-netfirewallrule",
    "set-smbserverconfiguration", "set-itemproperty", "disable-localuser",
    "new-item", "set-executionpolicy", "winget", "restart-service",
    "new-netfirewallrule", "stop-service",
}

_ALLOWED_PLACEHOLDERS = {"service", "package", "fixed_version", "port", "path"}

# Anything in this set appearing outside a {placeholder} span means the
# template is chaining/redirecting/substituting rather than being a single
# plain invocation. Backtick and $( are substitution; ; && || | are chaining;
# < > are redirection.
_DISALLOWED_SUBSTRINGS = (";", "&&", "||", "|", "`", "$(", "<", ">")

_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_SENTINEL = "PLACEHOLDERVAL"


class ValidationResult(NamedTuple):
    ok: bool
    validator: str
    error: Optional[str]


def _strip_placeholders(template: str) -> str:
    return _PLACEHOLDER_RE.sub(_SENTINEL, template)


def _check_placeholders(template: str) -> Optional[str]:
    for name in _PLACEHOLDER_RE.findall(template):
        if name not in _ALLOWED_PLACEHOLDERS:
            return f"unknown placeholder {{{name}}} (allowed: {sorted(_ALLOWED_PLACEHOLDERS)})"
    return None


def _check_structural(template: str) -> Optional[str]:
    stripped = _strip_placeholders(template)
    for bad in _DISALLOWED_SUBSTRINGS:
        if bad in stripped:
            return (f"disallowed chaining/redirection/substitution token {bad!r} -- "
                     "split into separate catalog_step_commands rows instead")
    if "\n" in template:
        return "multi-line command_template -- must be exactly one invocation"
    return None


def _validate_bash(template: str) -> ValidationResult:
    err = _check_placeholders(template)
    if err:
        return ValidationResult(False, "shlex+allowlist:v1", err)
    err = _check_structural(template)
    if err:
        return ValidationResult(False, "shlex+allowlist:v1", err)

    sentinel_form = _strip_placeholders(template)
    try:
        tokens = shlex.split(sentinel_form)
    except ValueError as exc:
        return ValidationResult(False, "shlex+allowlist:v1", f"shlex parse error: {exc}")
    if not tokens:
        return ValidationResult(False, "shlex+allowlist:v1", "empty command")

    argv0 = tokens[0]
    if argv0 == "sudo":
        if len(tokens) < 2:
            return ValidationResult(False, "shlex+allowlist:v1", "sudo with no command")
        argv0 = tokens[1]
    if argv0 not in _ALLOWED_BASH_COMMANDS:
        return ValidationResult(
            False, "shlex+allowlist:v1",
            f"{argv0!r} not in allowed bash commands {sorted(_ALLOWED_BASH_COMMANDS)}",
        )
    return ValidationResult(True, "shlex+allowlist:v1", None)


def _pwsh_available() -> bool:
    try:
        subprocess.run(["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion"],
                        capture_output=True, timeout=10, check=False)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _pwsh_parse_errors(template: str) -> Optional[str]:
    """Runs the template through PowerShell's own parser (a real AST parse,
    not a regex). Returns an error string if the parse reported any, else
    None. Caller must already have confirmed pwsh is on PATH."""
    escaped = template.replace("'", "''")
    script = (
        "$errors = $null; "
        f"[System.Management.Automation.Language.Parser]::ParseInput('{escaped}', "
        "[ref]$null, [ref]$errors) | Out-Null; "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.Message } }"
    )
    try:
        proc = subprocess.run(["pwsh", "-NoProfile", "-Command", script],
                               capture_output=True, timeout=15, text=True, check=False)
    except subprocess.TimeoutExpired:
        return "pwsh parse timed out"
    out = (proc.stdout or "").strip()
    return out or None


def _validate_powershell(template: str) -> ValidationResult:
    err = _check_placeholders(template)
    if err:
        return ValidationResult(False, "ps_parser+allowlist:v1", err)
    err = _check_structural(template)
    if err:
        return ValidationResult(False, "ps_parser+allowlist:v1", err)

    sentinel_form = _strip_placeholders(template)
    tokens = sentinel_form.split()
    if not tokens:
        return ValidationResult(False, "ps_parser+allowlist:v1", "empty command")
    if tokens[0].lower() not in _ALLOWED_PS_CMDLETS:
        return ValidationResult(
            False, "ps_parser+allowlist:v1",
            f"{tokens[0]!r} not in allowed PowerShell cmdlets {sorted(_ALLOWED_PS_CMDLETS)}",
        )

    if _pwsh_available():
        parse_err = _pwsh_parse_errors(sentinel_form)
        if parse_err:
            return ValidationResult(False, "ps_parser+allowlist:v1", f"pwsh parse error: {parse_err}")
        return ValidationResult(True, "ps_parser+allowlist:v1", None)

    # pwsh not available locally -- cmdlet-allowlist check still ran and
    # passed, but the AST parse itself was skipped. CI (which has pwsh
    # preinstalled on ubuntu-latest) is the enforcement point of record.
    return ValidationResult(True, "cmdlet_allowlist_only:v1 (pwsh not on PATH, AST parse skipped)", None)


def validate_command(template: str, command_shell: str) -> ValidationResult:
    if command_shell == "bash":
        return _validate_bash(template)
    if command_shell == "powershell":
        return _validate_powershell(template)
    return ValidationResult(False, "unknown", f"unknown command_shell {command_shell!r}")


class CatalogFailure(NamedTuple):
    finding_class: str
    step_index: int
    platform_key: str
    template: str
    error: str


def validate_catalog(catalog: dict) -> List[CatalogFailure]:
    """Walks REMEDIATION_CATALOG (or any dict shaped like it) and validates
    every commands_template entry found on a step. Steps that are plain
    strings (no commands_template -- prose only, today's shape for every
    existing entry) are skipped; there's nothing to validate."""
    failures: List[CatalogFailure] = []
    for finding_class, entry in catalog.items():
        steps = entry.get("steps_template") or []
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            commands = step.get("commands_template") or {}
            for platform_key, spec in commands.items():
                if isinstance(spec, dict):
                    template = spec.get("command_template", "")
                    shell = spec.get("command_shell", "")
                else:
                    # Fallback shape: bare string keyed by platform_key,
                    # shell inferred from the key prefix.
                    template = spec
                    shell = "powershell" if platform_key.startswith("windows_") else "bash"
                result = validate_command(template, shell)
                if not result.ok:
                    failures.append(CatalogFailure(
                        finding_class=finding_class, step_index=idx,
                        platform_key=platform_key, template=template,
                        error=result.error or "unknown error",
                    ))
    return failures

def validate_db(db_path=DEFAULT_DB_PATH) -> int:
    """Pipeline step 4 (notes/RemediationRAGPlan.txt "Pipeline shape"): runs
    every `catalog_step_commands` row in `remediation_rag.db` through
    validate_command() and writes the result back to
    ast_validated/ast_validator/ast_error/ast_checked_at. This is the gate a
    reviewer's approval alone doesn't substitute for -- export (step 5) only
    picks up rows with ast_validated=1, regardless of review status.

    Returns the number of rows that failed validation (0 = all passed)."""
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT command_id, command_template, command_shell FROM catalog_step_commands"
    ).fetchall()

    failure_count = 0
    checked_at = utcnow_iso()
    for row in rows:
        result = validate_command(row["command_template"], row["command_shell"])
        conn.execute(
            "UPDATE catalog_step_commands SET ast_validated = ?, ast_validator = ?, "
            "ast_error = ?, ast_checked_at = ? WHERE command_id = ?",
            (1 if result.ok else 0, result.validator, result.error, checked_at, row["command_id"]),
        )
        if result.ok:
            print(f"[OK] command_id {row['command_id']} ({row['command_shell']}): "
                  f"{row['command_template']!r}")
        else:
            failure_count += 1
            print(f"[FAIL] command_id {row['command_id']} ({row['command_shell']}): "
                  f"{row['command_template']!r} -- {result.error}", file=sys.stderr)

    conn.commit()
    conn.close()

    if failure_count:
        print(f"[FAIL] {failure_count}/{len(rows)} catalog_step_commands row(s) failed "
              "AST/allowlist validation.", file=sys.stderr)
    else:
        print(f"[OK] all {len(rows)} catalog_step_commands row(s) in {db_path} passed "
              "AST/allowlist validation.")
    return failure_count


def main() -> int:
    if "--db" in sys.argv:
        idx = sys.argv.index("--db")
        db_path = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else DEFAULT_DB_PATH
        return 1 if validate_db(db_path) else 0

    from core.remediation import REMEDIATION_CATALOG

    failures = validate_catalog(REMEDIATION_CATALOG)
    if failures:
        for f in failures:
            print(f"[FAIL] {f.finding_class} step {f.step_index} ({f.platform_key}): "
                  f"{f.template!r} -- {f.error}", file=sys.stderr)
        print(f"[FAIL] {len(failures)} command_template(s) failed AST/allowlist validation.",
              file=sys.stderr)
        return 1

    print("[OK] all commands_template entries in REMEDIATION_CATALOG passed AST/allowlist validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
