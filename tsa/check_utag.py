def get_bit(va: int, bit: int) -> int:
    return (va >> bit) & 1


def calculate_zen_utag(ptr: int) -> int:
    va = ptr & 0xFFFFFFFFFFFFFFFF

    u0 = (
        get_bit(va, 12) ^ get_bit(va, 13) ^ get_bit(va, 14) ^ get_bit(va, 15) ^
        get_bit(va, 16) ^ get_bit(va, 17) ^ get_bit(va, 18) ^ get_bit(va, 19) ^
        get_bit(va, 20) ^ get_bit(va, 21) ^ get_bit(va, 22) ^ get_bit(va, 23) ^
        get_bit(va, 24) ^ get_bit(va, 25) ^ get_bit(va, 26) ^ get_bit(va, 27)
    )

    u1 = get_bit(va, 13) ^ get_bit(va, 26)
    u2 = get_bit(va, 14) ^ get_bit(va, 25)
    u3 = get_bit(va, 19) ^ get_bit(va, 24)
    u4 = get_bit(va, 18) ^ get_bit(va, 23)
    u5 = get_bit(va, 17) ^ get_bit(va, 22)
    u6 = get_bit(va, 16) ^ get_bit(va, 21)
    u7 = get_bit(va, 15) ^ get_bit(va, 20)

    return (
        (u0 << 0) |
        (u1 << 1) |
        (u2 << 2) |
        (u3 << 3) |
        (u4 << 4) |
        (u5 << 5) |
        (u6 << 6) |
        (u7 << 7)
    )


if __name__ == "__main__":
    addr = 0xff0000019486e000
    utag = calculate_zen_utag(addr)
    print(f"utag: {utag:#04x}")