# -*- coding: utf-8 -*-
"""synjones_des.py
完整移植自安徽大学 CAS 登录页的 des.js（简化变体 DES，密钥调度表与标准 DES 不同）。
仅用于登录 one.ahu.edu.cn 时计算 rsa = strEnc(username + password + lt, '1', '2', '3')。
纯 Python 实现，无第三方依赖。
"""

_S1 = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
       [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
_S2 = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
       [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
_S3 = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
       [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
_S4 = [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
       [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
_S5 = [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
       [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
_S6 = [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
       [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
_S7 = [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
       [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
_S8 = [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
       [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
_SBOXES = [_S1, _S2, _S3, _S4, _S5, _S6, _S7, _S8]

_P_PERMUTE = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]
_FP = [39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,
       35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24]
_LOOP = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
# PC-2 选择表（0-based 索引）
_PC2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,
        40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31]


def _str_to_bt(s: str):
    """字符串(<=4字符) -> 64 bit 列表，每字符 16 bit，不足补 0。"""
    bt = [0] * 64
    n = min(4, len(s))
    for i in range(n):
        k = ord(s[i])
        for j in range(16):
            bt[16 * i + j] = (k >> (15 - j)) & 1
    for p in range(n, 4):
        for q in range(16):
            bt[16 * p + q] = 0
    return bt


def _get_key_bytes(key: str):
    """key -> [64bit] 列表。"""
    out = []
    i = 0
    for i in range(len(key) // 4):
        out.append(_str_to_bt(key[i * 4:i * 4 + 4]))
    if len(key) % 4 > 0:
        out.append(_str_to_bt(key[i * 4:]))
    return out


def _bt4_to_hex(binary: str) -> str:
    return hex(int(binary, 2))[2:].upper()


def _bt64_to_hex(byte_data) -> str:
    hexs = ""
    for i in range(16):
        bt = "".join(str(byte_data[i * 4 + j]) for j in range(4))
        hexs += _bt4_to_hex(bt)
    return hexs


def _init_permute(original: list):
    ip = [0] * 64
    m, n = 1, 0
    for i in range(4):
        for j in range(7, -1, -1):
            ip[i * 8 + (7 - j)] = original[j * 8 + m]
            ip[i * 8 + (7 - j) + 32] = original[j * 8 + n]
        m += 2
        n += 2
    return ip


def _expand_permute(right: list):
    ep = [0] * 48
    for i in range(8):
        if i == 0:
            ep[0] = right[31]
        else:
            ep[i * 6] = right[i * 4 - 1]
        ep[i * 6 + 1] = right[i * 4]
        ep[i * 6 + 2] = right[i * 4 + 1]
        ep[i * 6 + 3] = right[i * 4 + 2]
        ep[i * 6 + 4] = right[i * 4 + 3]
        if i == 7:
            ep[i * 6 + 5] = right[0]
        else:
            ep[i * 6 + 5] = right[i * 4 + 4]
    return ep


def _sbox_permute(expand_byte: list):
    out = [0] * 32
    for m in range(8):
        i = expand_byte[m * 6] * 2 + expand_byte[m * 6 + 5]
        j = (expand_byte[m * 6 + 1] * 8 + expand_byte[m * 6 + 2] * 4
             + expand_byte[m * 6 + 3] * 2 + expand_byte[m * 6 + 4])
        v = _SBOXES[m][i][j]
        for t in range(4):
            out[m * 4 + t] = (v >> (3 - t)) & 1
    return out


def _p_permute(sbox_byte: list):
    return [sbox_byte[i] for i in _P_PERMUTE]


def _finally_permute(end_byte: list):
    return [end_byte[i] for i in _FP]


def _xor(a: list, b: list):
    return [x ^ y for x, y in zip(a, b)]


def _generate_keys(key_byte: list):
    key = [0] * 56
    for i in range(7):
        for j in range(8):
            key[i * 8 + j] = key_byte[8 * (7 - j) + i]
    keys = []
    for i in range(16):
        for _ in range(_LOOP[i]):
            temp_left = key[0]
            temp_right = key[28]
            for k in range(27):
                key[k] = key[k + 1]
                key[28 + k] = key[29 + k]
            key[27] = temp_left
            key[55] = temp_right
        keys.append([key[idx] for idx in _PC2])
    return keys


def _enc(data_byte: list, key_byte: list):
    keys = _generate_keys(key_byte)
    ip = _init_permute(data_byte)
    left = ip[:32]
    right = ip[32:]
    for i in range(16):
        temp_left = left[:]
        left = right[:]
        f = _xor(_p_permute(_sbox_permute(_xor(_expand_permute(right), keys[i]))), temp_left)
        right = f
    final = right + left
    return _finally_permute(final)


def str_enc(data: str, first_key: str, second_key: str, third_key: str) -> str:
    """等价 des.js strEnc(data, firstKey, secondKey, thirdKey)。"""
    if not data:
        return ""
    enc_data = ""
    first = _get_key_bytes(first_key)
    second = _get_key_bytes(second_key)
    third = _get_key_bytes(third_key)
    iterator = len(data) // 4
    remainder = len(data) % 4
    for i in range(iterator):
        temp = _str_to_bt(data[i * 4:i * 4 + 4])
        for kb in first:
            temp = _enc(temp, kb)
        for kb in second:
            temp = _enc(temp, kb)
        for kb in third:
            temp = _enc(temp, kb)
        enc_data += _bt64_to_hex(temp)
    if remainder > 0:
        temp = _str_to_bt(data[iterator * 4:])
        for kb in first:
            temp = _enc(temp, kb)
        for kb in second:
            temp = _enc(temp, kb)
        for kb in third:
            temp = _enc(temp, kb)
        enc_data += _bt64_to_hex(temp)
    return enc_data


if __name__ == "__main__":
    # 与 node 输出对比验证
    print("test1:", str_enc("test1234LT-x", "1", "2", "3"))
    print("node : D8D35E5019288C41C1BB5938DF9F2190B4F9266264870306")
