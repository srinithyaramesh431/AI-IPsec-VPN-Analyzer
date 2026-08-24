#!/usr/bin/env python3
"""
generate_configs.py
--------------------
Reads config_matrix.yaml and produces:
  1. A set of strongSwan `conn` blocks (one per valid combination) that
     can be appended to ipsec.conf on Ubuntu A / Ubuntu B in turn.
  2. A ground-truth JSON label file per combination, saved under
     ./generated/labels/. These labels are the source of truth used to
     train and evaluate the ML module later -- they are NOT inferred,
     they are what was actually configured.

Usage:
    python3 generate_configs.py --out ./generated --limit 60

This script only WRITES config text and JSON labels to local files.
It does not touch live ipsec.conf, and does not restart any service.
You copy the generated conn blocks into ipsec.conf on each VM yourself
(see docs/SETUP_GUIDE.md, Phase 1).
"""
import argparse
import itertools
import json
import os
import random
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def load_matrix(path):
    with open(path) as f:
        return yaml.safe_load(f)


def valid_combo(ike_version, mode, enc, dh, pfs, ipver, lifetime, replay, ttype):
    """Filter out combinations that are not realistic / not supported."""
    # IKEv1 aggressive mode is legacy and rare with GCM/ChaCha in practice,
    # but we keep it (it's a real, if weak, historical config) EXCEPT we
    # drop chacha20 pairing with ikev1 since strongSwan's ikev1 stack does
    # not negotiate it.
    if ike_version == "ikev1" and enc["name"] == "chacha20poly1305":
        return False
    if ike_version == "ikev2" and mode is not None:
        return False
    if ike_version == "ikev1" and mode is None:
        return False
    return True


def build_conn_block(conn_name, left, right, ike_version, mode, enc, dh, pfs,
                      ipver, lifetime, replay, ttype, idx):
    ike_str = f"{enc['name']}-sha256-{dh['name']}" if ike_version == "ikev2" \
        else f"{enc['name']}-sha1-{dh['name']}"
    esp_str = f"{enc['name']}-{dh['name']}" if pfs else f"{enc['name']}"

    lines = [f"conn {conn_name}"]
    lines.append(f"    keyexchange={ike_version}")
    if mode:
        lines.append(f"    aggressive={'yes' if mode == 'aggressive' else 'no'}")
    lines.append(f"    left={left}")
    lines.append(f"    right={right}")
    lines.append(f"    ike={ike_str}!")
    lines.append(f"    esp={esp_str}!")
    lines.append(f"    keylife={lifetime}s")
    lines.append(f"    replay_window={'32' if replay else '0'}")
    lines.append(f"    type=tunnel")
    lines.append(f"    auto=add")
    lines.append("")  # blank line separator
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", default=os.path.join(HERE, "config_matrix.yaml"))
    ap.add_argument("--out", default=os.path.join(HERE, "generated"))
    ap.add_argument("--limit", type=int, default=60,
                     help="Cap number of generated combinations (full matrix is large)")
    ap.add_argument("--left", default="192.168.10.10")
    ap.add_argument("--right", default="192.168.10.20")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)
    matrix = load_matrix(args.matrix)

    os.makedirs(args.out, exist_ok=True)
    labels_dir = os.path.join(args.out, "labels")
    os.makedirs(labels_dir, exist_ok=True)

    combos = []
    for ike_version in matrix["ike_versions"]:
        modes = matrix["modes"][ike_version] or [None]
        for mode in modes:
            for enc in matrix["encryption_algorithms"]:
                for dh in matrix["dh_groups"]:
                    for pfs in matrix["pfs"]:
                        for ipver in matrix["ip_versions"]:
                            for lifetime in matrix["key_lifetime_seconds"]:
                                for replay in matrix["replay_protection"]:
                                    for ttype in matrix["traffic_types"]:
                                        if valid_combo(ike_version, mode, enc, dh,
                                                        pfs, ipver, lifetime, replay, ttype):
                                            combos.append((ike_version, mode, enc, dh, pfs,
                                                            ipver, lifetime, replay, ttype))

    print(f"Total valid combinations: {len(combos)}")
    random.shuffle(combos)
    combos = combos[:args.limit]
    print(f"Generating {len(combos)} configs (--limit={args.limit})")

    conn_blocks = []
    for idx, (ike_version, mode, enc, dh, pfs, ipver, lifetime, replay, ttype) in enumerate(combos):
        conn_name = f"gen-{idx:03d}"
        block = build_conn_block(conn_name, args.left, args.right, ike_version, mode,
                                  enc, dh, pfs, ipver, lifetime, replay, ttype, idx)
        conn_blocks.append(block)

        label = {
            "conn_name": conn_name,
            "ike_version": ike_version,
            "mode": mode or ("main" if ike_version == "ikev2" else None),
            "encryption": enc["name"],
            "encryption_strength_label": enc["strength"],
            "dh_group": dh["name"],
            "dh_strength_label": dh["strength"],
            "pfs_enabled": pfs,
            "ip_version": ipver,
            "key_lifetime_seconds": lifetime,
            "replay_protection": replay,
            "traffic_type": ttype,
            "source": "configuration-supplied"  # ground truth, not inferred
        }
        with open(os.path.join(labels_dir, f"{conn_name}.json"), "w") as f:
            json.dump(label, f, indent=2)

    conf_out = os.path.join(args.out, "generated_conns.conf")
    with open(conf_out, "w") as f:
        f.write("\n".join(conn_blocks))

    print(f"Wrote {conf_out}")
    print(f"Wrote {len(combos)} label files to {labels_dir}")
    print("\nNext: append blocks from generated_conns.conf into ipsec.conf on")
    print("both VMs (matching conn names), then bring each one up in turn:")
    print("  sudo ipsec up gen-000")
    print("while capturing on the bridge/router interface with tcpdump.")


if __name__ == "__main__":
    main()
