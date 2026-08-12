"""Generate a local Ed25519 policy-signing pair into .env (plan §7.2, T08).

Idempotent: existing non-empty POLICY_SIGNING_KEY / POLICY_PUBLIC_KEY values
are left untouched, so re-running bootstrap never rotates keys behind your
back. There is deliberately no checked-in pair — a published signing key
would let anyone forge policy for deployments that kept the default.
"""

import sys
from pathlib import Path

from phulax_policy.signing import generate_keypair

ENV_FILE = Path(".env")
KEYS = ("POLICY_SIGNING_KEY", "POLICY_PUBLIC_KEY")


def main() -> int:
    if not ENV_FILE.exists():
        print("keys: no .env found — copy .env.example to .env first")
        return 1

    lines = ENV_FILE.read_text().splitlines()
    current = {}
    for line in lines:
        name, _, value = line.partition("=")
        if name in KEYS:
            current[name] = value.strip()

    if all(current.get(key) for key in KEYS):
        print("keys: policy keypair already present in .env — leaving it alone")
        return 0
    if any(current.get(key) for key in KEYS):
        print("keys: .env has only half a policy keypair — fix or clear both values")
        return 1

    private_key, public_key = generate_keypair()
    values = {"POLICY_SIGNING_KEY": private_key, "POLICY_PUBLIC_KEY": public_key}
    replaced = set()
    updated = []
    for line in lines:
        name = line.partition("=")[0]
        if name in KEYS:
            updated.append(f"{name}={values[name]}")
            replaced.add(name)
        else:
            updated.append(line)
    for name in KEYS:
        if name not in replaced:
            updated.append(f"{name}={values[name]}")

    ENV_FILE.write_text("\n".join(updated) + "\n")
    print(f"keys: generated policy keypair into .env (public: {public_key})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
