"""Public-key encoding adapter, evaluated offline only.

Decode a canonical prime-subgroup Edwards point, then apply the Ristretto
encoding formula to that SAME point. No new secret and no hash-to-group.
This is not an on-chain proof that an untrusted supplied image is correct.
Reference: https://ristretto.group/formulas/encoding.html
"""
import json
import pathlib
import hashlib

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def root(value):
    x = pow(value, (P + 3) // 8, P)
    if x*x % P != value:
        x = x * SQRT_M1 % P
    if x*x % P != value:
        raise ValueError("not a square")
    return (-x % P) if x & 1 else x


def add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = (bb-aa) % P, (dd-cc) % P, (dd+cc) % P, (bb+aa) % P
    return e*f % P, g*h % P, f*g % P, e*h % P


def mul(n, point):
    out = IDENTITY
    while n:
        if n & 1:
            out = add(out, point)
        point = add(point, point)
        n >>= 1
    return out


def decode_edwards(data):
    if len(data) != 32:
        raise ValueError("Edwards key must be 32 bytes")
    integer = int.from_bytes(data, "little")
    sign, y = integer >> 255, integer & (2**255 - 1)
    if y >= P:
        raise ValueError("noncanonical Edwards y")
    y2 = y*y % P
    x = root((y2-1) * pow((D*y2+1) % P, -1, P) % P)
    if x == 0 and sign:
        raise ValueError("noncanonical Edwards zero sign")
    if (x & 1) != sign:
        x = -x % P
    point = x, y, 1, x*y % P
    check = mul(Q, point)
    if check[0] != 0 or (check[1]-check[2]) % P:
        raise ValueError("Edwards key not in prime-order subgroup")
    return point


def encode_ristretto(point):
    x, y, z, t = point
    if x == 0 and (y-z) % P == 0:
        return bytes(32)
    u1 = (z+y)*(z-y) % P
    u2 = x*y % P
    invsqrt = root(pow(u1*u2*u2 % P, -1, P))
    i1, i2 = invsqrt*u1 % P, invsqrt*u2 % P
    z_inv = i1*i2*t % P
    den_inv = i2
    if (t*z_inv % P) & 1:
        x, y = y*SQRT_M1 % P, x*SQRT_M1 % P
        den_inv = i1*root(pow((-1-D) % P, -1, P)) % P
    if (x*z_inv % P) & 1:
        y = -y % P
    s = den_inv*(z-y) % P
    if s & 1:
        s = -s % P
    return s.to_bytes(32, "little")


def convert(public_key_hex):
    return encode_ristretto(decode_edwards(bytes.fromhex(public_key_hex))).hex()


def affine(point):
    x, y, z, _ = point
    zi = pow(z, -1, P)
    x, y = x*zi % P, y*zi % P
    return x, y, 1, x*y % P


def ed_encode(point):
    x, y, _, _ = affine(point)
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def conversion_hint(ed):
    """Public, checkable arithmetic witnesses; contains no signing secret."""
    point = decode_edwards(ed)
    x, y, _, _ = point
    preimage = affine(mul(pow(8, -1, Q), point))
    r = 0 if x == 0 and y == 1 else root(pow((1-y*y)*x*x*y*y % P, -1, P))
    return (x.to_bytes(32, "little") + ed_encode(preimage)
            + preimage[0].to_bytes(32, "little") + r.to_bytes(32, "little"))


def hash_group_with_hints(label):
    hints = b""
    for counter in range(64):
        ed = hashlib.sha512(b"WTAS/Edwards/hash-to-group/v1" + label + counter.to_bytes(8, "little")).digest()[:32]
        enc = int.from_bytes(ed, "little")
        sign, y = enc >> 255, enc & (2**255 - 1)
        if y >= P:
            hints += bytes(32)
            continue
        ratio = (y*y-1) * pow((D*y*y+1) % P, -1, P) % P
        try:
            x = root(ratio)
        except ValueError:
            hints += root(2*ratio % P).to_bytes(32, "little")
            continue
        if (x & 1) != sign:
            x = -x % P
        hints += x.to_bytes(32, "little")
        if x == 0 and sign:
            continue
        point = affine(mul(8, (x, y, 1, x*y % P)))
        if point == IDENTITY:
            continue
        output = ed_encode(point)
        return output, conversion_hint(output), hints
    raise ValueError("hash-to-group exceeded on-chain counter bound")


def main():
    directory = pathlib.Path(__file__).resolve().parent / "edwards-results"
    data = json.loads((directory / "statement-proof.json").read_text())
    base = convert("58" + "66"*31)
    assert base == "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
    keys = [convert(pk) for pk in data["public_keys"]]
    aggregate = convert(data["aggregate_key_hex"])
    # The known honest scenario is 0-based even participants. No witness is
    # recovered here, and this is not a replacement for proof verification.
    selected = IDENTITY
    for i, (pk, weight) in enumerate(zip(data["public_keys"], data["weights"])):
        if i % 2 == 0:
            selected = add(selected, mul(weight, decode_edwards(bytes.fromhex(pk))))
    assert encode_ristretto(selected).hex() == aggregate
    result = dict(n=data["n"], edwards_keys=data["public_keys"], ristretto_images=keys,
                  edwards_aggregate_key=data["aggregate_key_hex"], ristretto_aggregate_image=aggregate,
                  basepoint_image=base, additional_private_keys_generated=0,
                  new_security_assumption_introduced=False,
                  offline_only=True, onchain_binding_implemented=False,
                  scope="Canonical prime-subgroup Edwards points only; direct encoding, not hash-to-group")
    (directory / "key-encoding-map.json").write_text(json.dumps(result, indent=2))
    print(f"Converted {len(keys)} actual Edwards public keys and aggregate K without private keys.")
    print("On-chain validation of this conversion remains to be implemented.")


if __name__ == "__main__":
    main()
