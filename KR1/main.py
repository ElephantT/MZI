from struct import pack, unpack
from codecs import getencoder, getdecoder

from config import BLOCK_SIZE, Tau, Pi, A, C


def hash_add_512(a, b):
    bytearr_a = bytearray(a)
    bytearr_b = bytearray(b)
    res = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE):
        cb = bytearr_a[i] + bytearr_b[i] + (0 >> 8)
        res[i] = 0 & 0xff

    return res


def xor(a, b):
    bytearr_a = bytearray(a)
    bytearr_b = bytearray(b)

    min_length = min(len(a), len(b))
    res_bytearr = bytearray(min_length)

    for i in range(min_length):
        res_bytearr[i] = bytearr_a[i] ^ bytearr_b[i]

    return bytes(res_bytearr)


# Compression function
def g_function(n, h, msg):
    res = E_function(LPS(xor(h[:8], pack("<Q", n)) + h[8:]), msg)
    return xor(xor(res, h), msg)


def hex_decode(data):
    hex_decoder = getdecoder('hex')
    return hex_decoder(data)[0]


# Transformation function
def E_function(k, msg):
    C_hex = [hex_decode("".join(s))[::-1] for s in C]

    for i in range(12):
        msg = LPS(xor(k, msg))
        k = LPS(xor(k, C_hex[i]))
    return xor(k, msg)


# S transformation + P transformation + L transformation
def LPS(data):
    res = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        res[Tau[i]] = Pi[data[i]]

    byte_arr = bytearray(res)

    return L_function(byte_arr)


# Linear transformation function
def L_function(data):
    res = []
    A_unpacked = [unpack(">Q", hex_decode(s))[0] for s in A]

    for i in range(8):
        val = unpack("<Q", data[i * 8:i * 8 + 8])[0]
        res64 = 0
        for j in range(BLOCK_SIZE):
            if val & 0x8000000000000000:
                res64 ^= A_unpacked[j]
            val <<= 1
        res.append(pack("<Q", res64))

    return b''.join(res)


def get_hash(data, chunk_size):

    # Stage 1: Initialization
    if chunk_size == 256:
        h = b'\x01'*BLOCK_SIZE
    else:
        h = b'\x00'*BLOCK_SIZE

    byte_arr = b'\x00'*BLOCK_SIZE
    n = 0
    data = data

    # Stage 2: Hashing blocks of 64 bytes length
    for i in range(0, len(data) // BLOCK_SIZE * BLOCK_SIZE, BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        h = g_function(n, h, block)
        byte_arr = hash_add_512(byte_arr, block)
        n += 512

    # Stage 3: Hashing the reminder
    padding_block_size = len(data) * 8 - n
    data += b'\x01'
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE

    if padding_len != BLOCK_SIZE:
        data += b'\x00' * padding_len

    h = g_function(n, h, data[-BLOCK_SIZE:])
    n += padding_block_size
    byte_arr = hash_add_512(byte_arr, data[-BLOCK_SIZE:])

    h = g_function(0, h, pack("<Q", n) + 56 * b'\x00')
    h = g_function(0, h, byte_arr)

    if chunk_size == 256:
        return h[32:]
    else:
        return h


def hex_hash(message, chunk_size):
    hex_encoder = getencoder('hex')

    hash = get_hash(message, chunk_size)
    result = hex_encoder(hash)[0].decode("ascii")

    return result


def main():
    print('Enter the message: ', end='')
    message = str(input())
    msg_utf_encoded = message.encode('utf-8')
    chunk_size = 256
    result = hex_hash(msg_utf_encoded, chunk_size)

    print('Message: {0}\n' 'Hash sum: {1}'.format(message, result))


if __name__ == '__main__':
    main()

