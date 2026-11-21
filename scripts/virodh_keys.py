"""
Manage Virodh API keys from a terminal (same SQLite store as the console).

    .venv\\Scripts\\python scripts\\virodh_keys.py create --name citizen-portal --policy default --rpm 60 --rpd 5000
    .venv\\Scripts\\python scripts\\virodh_keys.py list
    .venv\\Scripts\\python scripts\\virodh_keys.py revoke key_ab12cd34ef56
    .venv\\Scripts\\python scripts\\virodh_keys.py policies
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from virodh import config
from virodh.store import Store


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--name", required=True)
    c.add_argument("--policy", default="default")
    c.add_argument("--rpm", type=int, default=60)
    c.add_argument("--rpd", type=int, default=5000)
    c.add_argument("--models", default="", help="comma-separated allow-list (empty = all)")
    sub.add_parser("list")
    r = sub.add_parser("revoke")
    r.add_argument("key_id")
    sub.add_parser("policies")
    a = ap.parse_args()

    cfg = config.load()
    st = Store(cfg["storage"]["db_path"])
    st.seed_policies(cfg.get("policies", {}))
    if a.cmd == "create":
        if st.get_policy(a.policy, 0) is None:
            sys.exit(f"unknown policy '{a.policy}' (see: virodh_keys.py policies)")
        models = [m for m in a.models.split(",") if m]
        bad = [m for m in models if m not in cfg["models"]]
        if bad:
            sys.exit(f"unknown model(s): {bad}")
        secret, rec = st.create_key(a.name, a.policy, a.rpm, a.rpd, models)
        print(f"Created {rec.id} ({rec.name}, policy {rec.policy}, {rec.rpm}/min, {rec.rpd}/day)")
        print(f"\n  {secret}\n\nStore it now: only its hash is kept.")
    elif a.cmd == "list":
        for k in st.list_keys():
            used = time.strftime("%Y-%m-%d %H:%M", time.localtime(k["last_used"])) if k["last_used"] else "never"
            print(
                f"{k['id']:18} {k['name'][:24]:24} {k['prefix']:14} {k['policy']:22} {k['rpm']:>5}/min "
                f"{'REVOKED' if k['revoked'] else 'active ':7} last used {used}"
            )
    elif a.cmd == "revoke":
        print("revoked" if st.update_key(a.key_id, revoked=True) else "no such key")
    elif a.cmd == "policies":
        for p in st.list_policies():
            print(f"{p['name']:22} {p['mode']:8} {p['description']}")
    st.close()


if __name__ == "__main__":
    main()
