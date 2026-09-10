#!/usr/bin/env python3
"""Derive the 8 canonical small-order (8-torsion) point encodings for ed25519.

Method (no literature constants trusted blindly):
  1. Take arbitrary 32-byte candidates, decompress on-curve points.
  2. Compute T = [L]R with the target contract's own scalarmult — T lands in
     the 8-torsion subgroup; keep T when it has order exactly 8.
  3. The subgroup <T> = {O, T, 2T, ..., 7T} is the FULL 8-torsion; compress
     each element -> exactly 8 canonical encodings.
  4. Self-verify: [8]P == identity for every element; encodings distinct.

Prints the blacklist as Python + JS constants.
"""
import hashlib
import sys
import types
from pathlib import Path

CONTRACT = Path(__file__).resolve().parents[1] / "contracts" / "gendid_judge.py"


def load_contract():
    gl_mod = types.ModuleType("genlayer")

    class _TreeMap(dict):
        def get(self, k, default=None):
            try:
                return self[k]
            except KeyError:
                return default

    class UserError(Exception):
        pass

    gl_mod.gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        public=types.SimpleNamespace(
            view=lambda f=None: (f if f is not None else True),
            write=lambda f=None: (f if f is not None else True),
        ),
        message_raw={"datetime": "2026-09-10T00:00:00Z"},
        vm=types.SimpleNamespace(run_nondet=lambda a, b: {}),
        nondet=types.SimpleNamespace(exec_prompt=lambda p, response_format=None: ""),
        TreeMap=_TreeMap,
        u256=int,
        UserError=UserError,
    )
    gl_mod.UserError = UserError
    gl_mod.TreeMap = _TreeMap
    gl_mod.u256 = int
    gl_mod.__all__ = ["gl", "UserError", "TreeMap", "u256"]
    sys.modules["genlayer"] = gl_mod
    mod = types.ModuleType("gendid")
    mod.__dict__["__name__"] = "gendid"
    exec(compile(CONTRACT.read_text(), str(CONTRACT), "exec"), mod.__dict__)
    return mod


G = load_contract()
P, L, D, GY = G._P, G._L, G._D, G._GY
IDENTITY_ENC = bytes([1]) + bytes(31)


def on_curve_point(seed_int: int):
    enc = (seed_int % (1 << 255)).to_bytes(32, "little")
    pt = G._point_decompress(enc)
    return enc, pt


def main():
    # find a point T of order exactly 8: T = [L]R for random-ish on-curve R
    T = None
    seed = 0
    while T is None:
        seed += 1
        enc, R = on_curve_point(seed * 0x9E3779B97F4A7C15 % (1 << 255))
        if R is None:
            continue
        cand = G._scalarmult(R, L)
        # order of cand: 8 iff [4]cand != identity and [8]cand == identity
        if G._compress(cand) == IDENTITY_ENC:
            continue
        if G._compress(G._scalarmult(cand, 4)) == IDENTITY_ENC:
            continue  # order 4 (can't happen for [L]R? guard anyway)
        if G._compress(G._scalarmult(cand, 8)) != IDENTITY_ENC:
            raise SystemExit("arithmetic broken: [L]R not in 8-torsion")
        T = cand
    print(f"# order-8 point found from seed {seed}")

    subgroup = [G._scalarmult(T, i) for i in range(8)]
    encs = []
    for pt in subgroup:
        e = G._compress(pt)
        # self-verify: [8]pt == identity
        assert G._compress(G._scalarmult(pt, 8)) == IDENTITY_ENC, "not torsion"
        encs.append(e.hex())
    assert len(set(encs)) == 8, "encodings not distinct"
    assert IDENTITY_ENC.hex() in encs, "identity missing"

    # cross-check with the well-known literature constants (prefixes)
    known_prefixes = {
        "identity": "01" + "00" * 31,
        "order2": "ec" + "ff" * 30 + "7f",
        "order4": "26e8958f",
        "order8c717": "c7176a70",
    }
    print("\n# 8 canonical small-order encodings (little-endian hex):")
    for e in sorted(encs):
        note = ""
        if e == known_prefixes["identity"]:
            note = "  <- identity (order 1)"
        elif e == known_prefixes["order2"]:
            note = "  <- (0, p-1) order 2"
        elif e.startswith("26e8958f"):
            note = "  <- literature 26e8958f... (order 8)"
        elif e.startswith("c7176a70"):
            note = "  <- literature c7176a70... (order 8)"
        print(f"  {e}{note}")

    y0 = ("00" * 32)
    y0b = ("00" * 31 + "80")
    print(f"\n# order-4 (±sqrt(-1), 0) encodings present: "
          f"{y0 in [e for e in encs]} / {y0b in [e for e in encs]}")

    print("\n# Python constant:")
    print("_SMALL_ORDER_ENC_HEX = (")
    for e in sorted(encs):
        print(f'    "{e}",')
    print(")")
    print("\n# JS constant:")
    print("const SMALL_ORDER_ENC_HEX = [")
    for e in sorted(encs):
        print(f'  "{e}",')
    print("];")

    # non-canonical x=0 / sign=1 companions (rejected by contract decompress;
    # JS must blacklist them by bytes):
    print('\n# non-canonical x=0,sign=1 forms (contract: decompress rejects; JS: byte blacklist):')
    print(f'#   81{"00"*31}   (y=1, sign=1)')
    print(f'#   ec{"ff"*30}ff   (y=p-1, sign=1)')


if __name__ == "__main__":
    main()
