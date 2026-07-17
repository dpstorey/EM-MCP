from __future__ import annotations

import asyncio
import os
import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP


WORKSPACE = Path(os.environ.get("WORKSPACE", "/llm-scratch")).resolve()
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", "120"))
MAX_OUTPUT = int(os.environ.get("MAX_OUTPUT", "100000"))

# Commands that should never be available inside the workspace container.
BLOCKED_EXECUTABLES = {
    "docker",
    "podman",
    "kubectl",
    "systemctl",
    "service",
    "sudo",
    "su",
    "mount",
    "umount",
    "nsenter",
    "chroot",
    "shutdown",
    "reboot",
    "poweroff",
}

mcp = FastMCP(
    "workspace-shell",
    instructions="""
This server provides a Linux shell inside an isolated workspace container.

Rules:
- Use /llm-scratch as the working directory.
- Do not use /mnt/data.
- Do not attempt to access the Docker host or other containers.
- Prefer ordinary shell tools such as jq, grep, sed, awk, find, Python,
  Node, Pandoc, zip and unzip.
- Check command results before claiming success.
- Generated reports and temporary files must remain under /llm-scratch.
""",
host="0.0.0.0",
port=8000,
)


def safe_path(path: str | None) -> Path:
    """Resolve a path and ensure it stays inside the permitted workspace."""
    candidate = WORKSPACE if not path else Path(path)

    if not candidate.is_absolute():
        candidate = WORKSPACE / candidate

    resolved = candidate.resolve()

    try:
        resolved.relative_to(WORKSPACE)
    except ValueError as exc:
        raise ValueError(
            f"Path must remain beneath {WORKSPACE}; rejected: {resolved}"
        ) from exc

    return resolved


def validate_command(command: str) -> None:
    """
    Apply a basic executable deny-list.

    Container isolation remains the primary security boundary. This check is an
    additional guardrail, not a complete shell parser or security sandbox.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid shell command: {exc}") from exc

    for token in tokens:
        executable = Path(token).name
        if executable in BLOCKED_EXECUTABLES:
            raise ValueError(f"Executable is not permitted: {executable}")


@mcp.tool()
async def run_command(
    command: str,
    working_directory: str = "/llm-scratch",
    timeout_seconds: int = COMMAND_TIMEOUT,
) -> dict:
    """
    Run a shell command in the isolated Linux workspace.

    Args:
        command: Bash command to execute.
        working_directory: Directory beneath /llm-scratch in which to run it.
        timeout_seconds: Maximum execution time, capped at 300 seconds.

    Returns:
        Exit code, stdout, stderr, working directory and truncation status.
    """
    validate_command(command)
    cwd = safe_path(working_directory)

    if not cwd.exists():
        raise ValueError(f"Working directory does not exist: {cwd}")
    if not cwd.is_dir():
        raise ValueError(f"Working directory is not a directory: {cwd}")

    timeout = max(1, min(timeout_seconds, 300))

    process = await asyncio.create_subprocess_exec(
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        command,
        cwd=str(cwd),
        env={
            "PATH": os.environ.get(
                "PATH",
                "/usr/local/bin:/usr/bin:/bin",
            ),
            "HOME": str(WORKSPACE),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "WORKSPACE": str(WORKSPACE),
        },
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "exit_code": None,
            "stdout": "",
            "stderr": f"Command exceeded {timeout} seconds and was terminated.",
            "working_directory": str(cwd),
            "timed_out": True,
            "truncated": False,
        }

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    truncated = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT

    return {
        "exit_code": process.returncode,
        "stdout": stdout[:MAX_OUTPUT],
        "stderr": stderr[:MAX_OUTPUT],
        "working_directory": str(cwd),
        "timed_out": False,
        "truncated": truncated,
    }


@mcp.tool()
def list_installed_tools() -> str:
    """List useful command-line tools installed in the workspace container."""
    return """
Available workspace tools include:

Shell and text:
- bash
- grep
- sed
- awk
- find
- xargs
- sort
- cut
- diff
- jq

Languages:
- python3
- node
- npm

Documents and archives:
- pandoc
- zip
- unzip
- tar
- gzip

Network clients:
- curl
- wget

Version control:
- git

Workspace root:
- /llm-scratch
""".strip()


if __name__ == "__main__":
    # FastMCP's HTTP endpoint is normally exposed at /mcp.
    mcp.run(transport="streamable-http")
