"""Reed–Solomon over GF(2^8) for format v5 parity (docs/format-v5.md).

Field polynomial 0x11d, primitive element alpha = 2, first consecutive root
alpha^0 (fcr 0) and root step 1: the generator of an RS(k + p, k) code is
g(x) = (x - alpha^0)(x - alpha^1)...(x - alpha^(p-1)). Codewords are
systematic, data symbols first: c = data || parity, read as the polynomial
c[0] x^(n-1) + ... + c[n-1], so c(x) = data(x) x^p + (data(x) x^p mod g(x)).
Codes are shortened (n = k + p <= 255).

Independent pure-Python reference for the kernel implementation in
kernel/piv-native.inc. Decoding never authenticates anything: callers accept
a corrected record only through its SIV tag.
"""

POLY = 0x11d
EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= POLY
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]
del _x, _i


class DecodeError(ValueError):
    """Too many errors and erasures (or an inconsistent decoding)."""


def mul(a, b):
    return EXP[LOG[a] + LOG[b]] if a and b else 0


def div(a, b):
    if not b:
        raise ZeroDivisionError('GF(256) division by zero')
    return EXP[LOG[a] + 255 - LOG[b]] if a else 0


def alpha_power(n):
    return EXP[n % 255]


def generator(parity):
    """g(x) coefficients, highest degree first (g[0] == 1)."""
    g = [1]
    for i in range(parity):
        # g(x) * (x + alpha^i)
        g = [a ^ mul(b, EXP[i]) for a, b in zip(g + [0], [0] + g)]
    return g


def encode(data, parity):
    """The @parity symbols completing the systematic codeword data || parity."""
    if parity < 1 or len(data) + parity > 255:
        raise ValueError('Invalid RS code length')
    g = generator(parity)
    remainder = [0] * parity
    for symbol in data:
        factor = symbol ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for i in range(parity):
                remainder[i] ^= mul(g[i + 1], factor)
    return remainder


def syndromes(codeword, parity):
    """S_i = c(alpha^i) for i < parity."""
    out = []
    for i in range(parity):
        value = 0
        for symbol in codeword:
            value = mul(value, EXP[i]) ^ symbol
        out.append(value)
    return out


def _evaluate(poly, x):
    """Ascending-coefficient polynomial at x."""
    value = 0
    for coefficient in reversed(poly):
        value = mul(value, x) ^ coefficient
    return value


def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] ^= mul(x, y)
    return out


def _berlekamp_massey(sequence):
    """Shortest connection polynomial (ascending, C[0] == 1) and its length L."""
    c, b = [1], [1]
    length, shift, last = 0, 1, 1
    for n, s in enumerate(sequence):
        d = s
        for i in range(1, length + 1):
            if i < len(c):
                d ^= mul(c[i], sequence[n - i])
        if not d:
            shift += 1
            continue
        coefficient = div(d, last)
        update = [0] * shift + [mul(coefficient, x) for x in b]
        new = [x ^ y for x, y in zip(c + [0] * (len(update) - len(c)), update + [0] * (len(c) - len(update)))]
        if 2 * length <= n:
            b, length, last, shift = c, n + 1 - length, d, 1
        else:
            shift += 1
        c = new
    while len(c) > 1 and not c[-1]:
        c.pop()
    return c, length


def decode(codeword, parity, erasures=()):
    """Errors-and-erasures decoding of one shortened codeword (in a copy).

    @erasures are codeword indices known to be unreliable. Corrects any e
    errors and f erasures with 2e + f <= parity, otherwise raises DecodeError
    (a miscorrection beyond that bound is possible; callers authenticate).
    """
    n = len(codeword)
    if parity < 1 or n <= parity or n > 255:
        raise ValueError('Invalid RS code length')
    erasures = sorted(set(erasures))
    if any(not 0 <= k < n for k in erasures):
        raise ValueError('Erasure outside the codeword')
    if len(erasures) > parity:
        raise DecodeError('More erasures than parity symbols')
    out = list(codeword)
    s = syndromes(out, parity)
    if not any(s):
        return out
    # Erasure locator Gamma(x) = prod (1 - X_k x), X_k = alpha^(n-1-k).
    gamma = [1]
    for k in erasures:
        gamma = _poly_mul(gamma, [1, alpha_power(n - 1 - k)])
    # Forney syndromes: (S(x) Gamma(x) mod x^p) from degree f upwards.
    modified = _poly_mul(s, gamma)[:parity]
    sigma, errors = _berlekamp_massey(modified[len(erasures):])
    if 2 * errors + len(erasures) > parity or len(sigma) - 1 != errors:
        raise DecodeError('Uncorrectable codeword')
    locator = _poly_mul(sigma, gamma)
    while len(locator) > 1 and not locator[-1]:
        locator.pop()
    omega = _poly_mul(s, locator)[:parity]
    derivative = [locator[i] if i % 2 else 0 for i in range(1, len(locator))]
    found = 0
    for k in range(n):
        x = alpha_power(n - 1 - k)
        inverse = alpha_power(-(n - 1 - k))
        if _evaluate(locator, inverse):
            continue
        found += 1
        denominator = _evaluate(derivative, inverse)
        if not denominator:
            raise DecodeError('Uncorrectable codeword')
        out[k] ^= div(mul(x, _evaluate(omega, inverse)), denominator)
    if found != len(locator) - 1 or any(syndromes(out, parity)):
        raise DecodeError('Uncorrectable codeword')
    return out
