"""
Процесс формирования ЭЦП выполняется по следующему алгоритму:
Вычислить хеш сообщения M: H=h(M);
Вычислить целое число α, двоичным представлением которого является H;
Определить e=α mod q, если e=0, задать e=1;
Сгенерировать случайное число k, удовлетворяющее условию 0<k<q;
Вычислить точку эллиптической кривой C=k*P;
Определить r = xC mod q, где xC — x-координата точки C. Если r=0, то вернуться к шагу 4;
Вычислить значение s = (rd+ke) mod q. Если s=0, то вернуться к шагу 4;
Вернуть значение r||s в качестве цифровой подписи.
"""

from os import urandom
from hashlib import sha1
from codecs import getdecoder
from codecs import getencoder

from config import SIZE


def hex_encode(data):
    hex_encoder = getencoder('hex')
    return hex_encoder(data)[0].decode('ascii')


def hex_decode(data):
    hex_decoder = getdecoder('hex')
    return hex_decoder(data)[0]


def modinvert(a, n):
    if a < 0:
        return n - modinvert(-a, n)

    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotinent = r // new_r
        t, new_t = new_t, t - quotinent * new_t
        r, new_r = new_r, r - quotinent * new_r
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t


def bytes2long(raw):
    return int(hex_encode(raw), 16)


def long2bytes(n, size=SIZE):
    res = hex(int(n))[2:].rstrip("L")

    if len(res) % 2 != 0:
        res = "0" + res

    s = hex_decode(res)

    if len(s) != size:
        s = (size - len(s)) * b"\x00" + s

    return s


class GOST3410Curve(object):
    def __init__(self, p, q, a, b, x, y, e=None, d=None):
        self.p = p
        self.q = q
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        self.e = e
        self.d = d

        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p

        if r1 != self.pos(r2):
            raise ValueError("Invalid parameters")

        self._st = None

    def pos(self, v):
        if v < 0:
            return v + self.p
        return v

    def _add(self, p1x, p1y, p2x, p2y):
        if p1x == p2x and p1y == p2y:
            t = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            tx = self.pos(p2x - p1x) % self.p
            ty = self.pos(p2y - p1y) % self.p
            t = (ty * modinvert(tx, self.p)) % self.p

        tx = self.pos(t * t - p1x - p2x) % self.p
        ty = self.pos(t * (p1x - tx) - p1y) % self.p

        return tx, ty

    def exp(self, degree, x=None, y=None):
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        if degree == 0:
            raise ValueError("Bad degree value")
        degree -= 1
        while degree != 0:
            if degree & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            degree = degree >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty

    def st(self):
        if self.e is None or self.d is None:
            raise ValueError("non twisted Edwards curve")
        if self._st is not None:
            return self._st
        self._st = (
            self.pos(self.e - self.d) * modinvert(4, self.p) % self.p,
            (self.e + self.d) * modinvert(6, self.p) % self.p,
        )
        return self._st


# Generates public key from the private one
def public_key(curve, prv):
    return curve.exp(prv)


# Calculates signature for provided digest
def sign(curve, prv, digest):
    size = SIZE * 2
    q = curve.q
    e = 1 if (bytes2long(digest) % q == 0) else bytes2long(digest) % q

    while True:
        k = bytes2long(urandom(size)) % q
        if k == 0:
            continue
        r, _ = curve.exp(k)
        r %= q
        if r == 0:
            continue
        d = prv * r
        k *= e
        s = (d + k) % q
        if s == 0:
            continue
        break
    return long2bytes(s, size) + long2bytes(r, size)


# Verifies provided digest with the signature
def verify(curve, pub, digest, signature):
    size = SIZE * 2

    if len(signature) != size * 2:
        raise ValueError("Invalid signature length")

    q = curve.q
    p = curve.p
    s = bytes2long(signature[:size])
    r = bytes2long(signature[size:])

    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False

    e = bytes2long(digest) % curve.q

    if e == 0:
        e = 1
    v = modinvert(e, q)
    z1 = s * v % q
    z2 = q - r * v % q
    p1x, p1y = curve.exp(z1)
    q1x, q1y = curve.exp(z2, pub[0], pub[1])
    lm = q1x - p1x

    if lm < 0:
        lm += p
    lm = modinvert(lm, p)
    z1 = q1y - p1y
    lm = lm * z1 % p
    lm = lm * lm % p
    lm = lm - p1x - q1x
    lm = lm % p
    if lm < 0:
        lm += p
    lm %= q
    return lm == r


def prv_unmarshal(prv):
    return bytes2long(prv[::-1])


def pub_marshal(pub):
    return (long2bytes(pub[1], SIZE) + long2bytes(pub[0], SIZE))[::-1]


def pub_unmarshal(pub):
    pub = pub[::-1]
    return bytes2long(pub[SIZE:]), bytes2long(pub[:SIZE])


# Converts Edwards curve U,V coordinates to Weierstrass X,Y
def uv2xy(curve, u, v):
    s, t = curve.st()
    k1 = (s * (1 + v)) % curve.p
    k2 = curve.pos(1 - v)
    x = t + k1 * modinvert(k2, curve.p)
    y = k1 * modinvert(u * k2, curve.p)
    return x % curve.p, y % curve.p


# Converts Weierstrass X, Y coordinates to Edwards curve U, V
def xy2uv(curve, x, y):
    s, t = curve.st()
    xmt = curve.pos(x - t)
    u = xmt * modinvert(y, curve.p)
    v = curve.pos(xmt - s) * modinvert(xmt + s, curve.p)
    return u % curve.p, v % curve.p


def main():
    curve = GOST3410Curve(
        p=bytes2long(hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97")),
        q=bytes2long(hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893")),
        a=bytes2long(hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94")),
        b=bytes2long(hex_decode("00000000000000000000000000000000000000000000000000000000000000a6")),
        x=bytes2long(hex_decode("0000000000000000000000000000000000000000000000000000000000000001")),
        y=bytes2long(hex_decode("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14")),
    )

    prv_raw = urandom(32)
    prv = prv_unmarshal(prv_raw)
    pub = public_key(curve, prv)
    print("Public key:", hex_encode(pub_marshal(pub)))
    data_for_signing = b"some data"
    dgst = sha1(data_for_signing).digest()
    signature = sign(curve, prv, dgst)

    res = verify(curve, pub, dgst, signature)
    print("Verification result: ", 'OK' if res else 'NOT OK')


if __name__ == '__main__':
    main()
