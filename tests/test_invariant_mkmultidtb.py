import pytest
import subprocess
import sys
import os

@pytest.mark.parametrize("payload", [
    # Exact exploit case: shell metacharacter injection
    "dtb; rm -rf /tmp/pwned; echo",
    # Boundary case: backtick command substitution
    "dtb`touch /tmp/injected`",
    # Valid input: normal DTB filename
    "rk3399-sapphire.dtb",
])
def test_mkmultidtb_no_shell_injection(payload, tmp_path):
    """Invariant: mkmultidtb.py must not execute injected shell commands
    embedded in DTB filenames passed as arguments."""
    sentinel = tmp_path / "injected_marker"

    # Patch the payload to write to our sentinel if injection succeeds
    inject_payload = f"dtb; touch {sentinel}; echo"
    backtick_payload = f"dtb`touch {sentinel}`"

    if payload == "dtb; rm -rf /tmp/pwned; echo":
        test_payload = inject_payload
    elif payload == "dtb`touch /tmp/injected`":
        test_payload = backtick_payload
    else:
        test_payload = payload

    env = os.environ.copy()
    result = subprocess.run(
        [sys.executable, "scripts/mkmultidtb.py", test_payload],
        capture_output=True,
        text=True,
        env=env,
        cwd=os.getcwd(),
    )

    # The sentinel file must NOT exist — if it does, injection succeeded
    assert not sentinel.exists(), (
        f"Shell injection succeeded: sentinel file created by payload: {test_payload!r}"
    )