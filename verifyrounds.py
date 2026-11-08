from des import (E, FP, IP, P, PC1, PC2, S_BOXES, SHIFTS, f_function, generate_subkeys,
                 permute, rotate_left_28)

PLAINTEXT = b"TRANSFER"
KEY = b"LGCYBANK"

EXPECTED = {
    "K1": "A0924270F992",
    "L0": "FF936954",
    "R0": "000008BA",
    "f": "D7A8F857",
    "L1": "000008BA",
    "R1": "283B9103",
}


def bits(value, width, group=8):
    s = format(value, f"0{width}b")
    return " ".join(s[i:i + group] for i in range(0, width, group))


def hexs(value, width):
    return format(value, f"0{width // 4}X")


def check(name, value, width):
    ok = hexs(value, width) == EXPECTED[name]
    print(f"    check {name} = {hexs(value, width)}  expected {EXPECTED[name]}  ->  {'MATCH' if ok else 'MISMATCH'}")
    return ok


def main():
    results = []
    p64 = int.from_bytes(PLAINTEXT, "big")
    k64 = int.from_bytes(KEY, "big")

    print("=" * 78)
    print(" DES ROUND 1 VERIFICATION  |  plaintext 'TRANSFER'  |  key 'LGCYBANK'")
    print("=" * 78)
    print(f"Plaintext  (hex {hexs(p64, 64)}): {bits(p64, 64)}")
    print(f"Key        (hex {hexs(k64, 64)}): {bits(k64, 64)}")

    print("\nSTEP 1  Key generation")
    k56 = permute(k64, PC1, 64)
    print(f"  PC-1 (56 bits): {bits(k56, 56, 7)}")
    c0, d0 = k56 >> 28, k56 & 0x0FFFFFFF
    print(f"  C0: {bits(c0, 28, 7)}")
    print(f"  D0: {bits(d0, 28, 7)}")
    c1, d1 = rotate_left_28(c0, SHIFTS[0]), rotate_left_28(d0, SHIFTS[0])
    print(f"  C1 (shift 1): {bits(c1, 28, 7)}")
    print(f"  D1 (shift 1): {bits(d1, 28, 7)}")
    k1 = permute((c1 << 28) | d1, PC2, 56)
    print(f"  K1 = PC-2(C1D1): {bits(k1, 48, 6)}")
    results.append(check("K1", k1, 48))

    print("\nSTEP 2  Initial permutation")
    ip = permute(p64, IP, 64)
    print(f"  IP(P): {bits(ip, 64)}")

    print("\nSTEP 3  Split into L0 and R0")
    l0, r0 = ip >> 32, ip & 0xFFFFFFFF
    print(f"  L0: {bits(l0, 32, 4)}")
    print(f"  R0: {bits(r0, 32, 4)}")
    results.append(check("L0", l0, 32))
    results.append(check("R0", r0, 32))

    print("\nSTEP 4  Expansion E(R0), 32 -> 48 bits")
    e = permute(r0, E, 32)
    print(f"  E(R0): {bits(e, 48, 6)}")

    print("\nSTEP 5  XOR with K1")
    x = e ^ k1
    print(f"  E(R0) XOR K1: {bits(x, 48, 6)}")

    print("\nSTEP 6  S-box lookups")
    print("  S-box | Input  | Row | Column | Decimal | Binary")
    s_out = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk >> 4) & 0b10) | (chunk & 1)
        col = (chunk >> 1) & 0xF
        val = S_BOXES[i][row][col]
        s_out = (s_out << 4) | val
        print(f"  S{i + 1}    | {chunk:06b} | {row:>3} | {col:>6} | {val:>7} | {val:04b}")
    print(f"  S-box output: {bits(s_out, 32, 4)}")

    print("\nSTEP 7  Permutation P")
    f = permute(s_out, P, 32)
    print(f"  f(R0, K1) = P(S-box output): {bits(f, 32, 4)}")
    results.append(check("f", f, 32))

    print("\nSTEP 8  New right half R1 = L0 XOR f(R0, K1)")
    r1 = l0 ^ f
    print(f"  R1: {bits(r1, 32, 4)}")
    results.append(check("R1", r1, 32))

    print("\nSTEP 9  New left half L1 = R0")
    l1 = r0
    print(f"  L1: {bits(l1, 32, 4)}")
    results.append(check("L1", l1, 32))

    print("\nSTEP 10  Swap halves (R1 L1)")
    swapped = (r1 << 32) | l1
    print(f"  R1 L1: {bits(swapped, 64)}")

    print("\nSTEP 11  Inverse initial permutation IP^-1")
    c = permute(swapped, FP, 64)
    print(f"  One-round ciphertext: {bits(c, 64)}")
    print(f"  One-round ciphertext (hex): {hexs(c, 64)}")

    print("\nCROSS-CHECK against the full DES implementation in des.py")
    same_k1 = generate_subkeys(KEY)[0] == k1
    same_f = f_function(r0, k1) == f
    print(f"  generate_subkeys()[0] == K1   ->  {'MATCH' if same_k1 else 'MISMATCH'}")
    print(f"  f_function(R0, K1) == f       ->  {'MATCH' if same_f else 'MISMATCH'}")
    results += [same_k1, same_f]

    print("\n" + "=" * 78)
    print(f" RESULT: {sum(results)}/{len(results)} checks passed -> "
          f"{'Appendix A values are CORRECT' if all(results) else 'ERROR in Appendix A'}")
    print("=" * 78)


if __name__ == "__main__":
    main()