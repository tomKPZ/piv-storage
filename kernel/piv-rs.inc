/* SPDX-License-Identifier: GPL-2.0-only */
/* Format v5 Reed-Solomon parity (docs/format-v5.md). Self-contained: besides
 * the PN_* geometry constants it needs only memset/memmove,
 * memzero_explicit, test_bit and BITS_TO_LONGS, so the guest-only harness
 * kernel/piv-rs-test.c can cross-check it against pivstore/rs.py.
 */
/* Reed-Solomon over GF(2^8) (docs/format-v5.md): polynomial 0x11d, alpha = 2,
 * first consecutive root alpha^0, root step 1 (dm-verity's FEC parameters).
 * Systematic codewords data || parity, symbol 0 the highest-degree
 * coefficient; shortened to n = 229 + p symbols. Implemented here rather than
 * through lib/reed_solomon: the stock config guarantees neither the encoder
 * nor the decoder. Decoding never authenticates: a corrected record is
 * accepted only through its SIV tag. pivstore/rs.py is the independent
 * reference.
 */
static u8 pn_gf_exp[512], pn_gf_log[256];

static void pn_gf_init(void)
{
	u32 i, x = 1;
	for (i = 0; i < 255; i++) {
		pn_gf_exp[i] = x; pn_gf_log[x] = i;
		x <<= 1;
		if (x & 0x100) x ^= 0x11d;
	}
	for (i = 255; i < 512; i++) pn_gf_exp[i] = pn_gf_exp[i - 255];
}

static inline u8 pn_gf_mul(u8 a, u8 b) { return a && b ? pn_gf_exp[pn_gf_log[a] + pn_gf_log[b]] : 0; }
/* b != 0 */
static inline u8 pn_gf_div(u8 a, u8 b) { return a ? pn_gf_exp[pn_gf_log[a] + 255 - pn_gf_log[b]] : 0; }
static inline u8 pn_gf_pow(int e) { e %= 255; return pn_gf_exp[e < 0 ? e + 255 : e]; }

/* Ascending-coefficient polynomial of degree @deg at @x. */
static u8 pn_poly_eval(const u8 *poly, int deg, u8 x)
{
	u8 v = 0;
	for (; deg >= 0; deg--) v = pn_gf_mul(v, x) ^ poly[deg];
	return v;
}

/* g(x) = prod_{i<p} (x + alpha^i), highest degree first, g[0] = 1. */
static void pn_rs_generator(u32 p, u8 *g)
{
	u32 i, j;
	memset(g, 0, p + 1); g[0] = 1;
	for (i = 0; i < p; i++)
		for (j = i + 1; j > 0; j--) g[j] ^= pn_gf_mul(g[j - 1], pn_gf_exp[i]);
}

/* Parity of one codeword: remainder of data(x) x^p mod g(x). */
static void pn_rs_encode(const u8 *data, u32 k, u32 p, const u8 *g, u8 *rem)
{
	u32 i, j;
	memset(rem, 0, p);
	for (i = 0; i < k; i++) {
		u8 f = data[i] ^ rem[0];
		memmove(rem, rem + 1, p - 1); rem[p - 1] = 0;
		if (f) for (j = 0; j < p; j++) rem[j] ^= pn_gf_mul(g[j + 1], f);
	}
}

/* S_i = c(alpha^i); true if all p syndromes are zero. */
static bool pn_rs_syndromes(const u8 *c, u32 n, u32 p, u8 *s)
{
	u32 i, j;
	bool zero = true;
	for (i = 0; i < p; i++) {
		u8 v = 0;
		for (j = 0; j < n; j++) v = pn_gf_mul(v, pn_gf_exp[i]) ^ c[j];
		s[i] = v; zero &= !v;
	}
	return zero;
}

/* Errors-and-erasures decoding of one shortened codeword c[0..n) in place:
 * @f erasures at codeword indices @erasures. Corrects e errors with
 * 2e + f <= p; returns 0, or -1 when uncorrectable (c may be modified then).
 * Forney syndromes reduce erasures to an errors-only Berlekamp-Massey run;
 * Chien search and Forney's formula (fcr 0: e = X Omega(1/X) / Lambda'(1/X))
 * follow, and the corrected word must have zero syndromes.
 */
static int pn_rs_decode(u8 *c, u32 n, u32 p, const u8 *erasures, u32 f)
{
	u8 s[PN_MAX_PARITY], gamma[PN_MAX_PARITY + 1] = {}, mod[PN_MAX_PARITY];
	u8 C[2 * PN_MAX_PARITY + 2] = {}, B[2 * PN_MAX_PARITY + 2] = {}, T[2 * PN_MAX_PARITY + 2];
	u8 lambda[2 * PN_MAX_PARITY + 2] = {}, omega[PN_MAX_PARITY] = {};
	u32 i, j, k, m, L = 0, shift = 1, found = 0, gdeg = 0;
	int cdeg, ldeg;
	u8 last = 1;
	if (pn_rs_syndromes(c, n, p, s)) return 0;
	if (f > p) return -1;
	/* Gamma(x) = prod (1 + X_k x), X_k = alpha^(n - 1 - k). */
	gamma[0] = 1;
	for (k = 0; k < f; k++) {
		u8 x = pn_gf_pow(n - 1 - erasures[k]);
		for (j = ++gdeg; j > 0; j--) gamma[j] ^= pn_gf_mul(gamma[j - 1], x);
	}
	/* Forney syndromes: (S(x) Gamma(x) mod x^p) from degree f upwards. */
	for (i = 0; i < p; i++) {
		u8 v = 0;
		for (j = 0; j <= i && j <= gdeg; j++) v ^= pn_gf_mul(gamma[j], s[i - j]);
		mod[i] = v;
	}
	m = p - f;
	C[0] = 1; B[0] = 1;
	for (i = 0; i < m; i++) {
		u8 d = mod[f + i], coef;
		for (j = 1; j <= L; j++) d ^= pn_gf_mul(C[j], mod[f + i - j]);
		if (!d) { shift++; continue; }
		coef = pn_gf_div(d, last);
		memcpy(T, C, sizeof(T));
		for (j = 0; j + shift < sizeof(C); j++) C[j + shift] ^= pn_gf_mul(coef, B[j]);
		if (2 * L <= i) { L = i + 1 - L; memcpy(B, T, sizeof(B)); last = d; shift = 1; }
		else shift++;
	}
	for (cdeg = sizeof(C) - 1; cdeg > 0 && !C[cdeg]; cdeg--);
	if (2 * L + f > p || cdeg != (int)L) return -1;
	/* Lambda = sigma * Gamma; Omega = S Lambda mod x^p. */
	for (i = 0; i <= L; i++)
		for (j = 0; j <= gdeg; j++) lambda[i + j] ^= pn_gf_mul(C[i], gamma[j]);
	ldeg = L + gdeg;
	for (i = 0; i < p; i++)
		for (j = 0; j <= i && j <= (u32)ldeg; j++) omega[i] ^= pn_gf_mul(lambda[j], s[i - j]);
	for (k = 0; k < n; k++) {
		u8 inverse = pn_gf_pow(-(int)(n - 1 - k)), den = 0;
		if (pn_poly_eval(lambda, ldeg, inverse)) continue;
		found++;
		/* Lambda'(x) = sum over odd i of lambda_i x^(i-1) */
		for (j = 1; j <= (u32)ldeg; j += 2) den ^= pn_gf_mul(lambda[j], pn_gf_pow((int)(j - 1) * pn_gf_log[inverse]));
		if (!den) return -1;
		c[k] ^= pn_gf_div(pn_gf_mul(pn_gf_pow(n - 1 - k), pn_poly_eval(omega, p - 1, inverse)), den);
	}
	if (found != (u32)ldeg || !pn_rs_syndromes(c, n, p, s)) return -1;
	return 0;
}

/* 3p parity fragments of the 687 data fragments in @payload: lane l holds data
 * fragments j = 3i + l and parity fragment i at fragment index 687 + 3i + l;
 * byte b (0-5) of a lane's fragments is one RS(229 + p, 229) codeword.
 * @parity receives the 3p fragments (fragment 687 onwards).
 */
static void pn_rs_parity(const u8 *payload, u32 p, u8 *parity)
{
	u8 g[PN_MAX_PARITY + 1], word[PN_LANE_DATA], rem[PN_MAX_PARITY];
	u32 lane, b, i;
	pn_rs_generator(p, g);
	for (lane = 0; lane < PN_LANES; lane++)
		for (b = 0; b < PN_FRAGMENT; b++) {
			for (i = 0; i < PN_LANE_DATA; i++) word[i] = payload[(PN_LANES * i + lane) * PN_FRAGMENT + b];
			pn_rs_encode(word, PN_LANE_DATA, p, g, rem);
			for (i = 0; i < p; i++) parity[(PN_LANES * i + lane) * PN_FRAGMENT + b] = rem[i];
		}
	memzero_explicit(word, sizeof(word)); memzero_explicit(rem, sizeof(rem));
}

/* Correct the data fragments of @fragments (687 + 3p) in place, using the
 * sectors in @erased (fragment indices) as erasures. -1 if any lane fails.
 */
static int pn_rs_correct(u8 *fragments, u32 p, const unsigned long *erased)
{
	u8 word[PN_LANE_DATA + PN_MAX_PARITY], lost[PN_MAX_PARITY];
	u32 lane, b, i, f;
	int r = 0;
	for (lane = 0; !r && lane < PN_LANES; lane++) {
		for (i = 0, f = 0; !r && i < PN_LANE_DATA + p; i++) {
			u32 j = i < PN_LANE_DATA ? PN_LANES * i + lane : PN_DATA_FRAGMENTS + PN_LANES * (i - PN_LANE_DATA) + lane;
			if (!erased || !test_bit(j, erased)) continue;
			if (f == p) r = -1;	/* more erasures than parity in this lane */
			else lost[f++] = i;
		}
		for (b = 0; !r && b < PN_FRAGMENT; b++) {
			for (i = 0; i < PN_LANE_DATA + p; i++) {
				u32 j = i < PN_LANE_DATA ? PN_LANES * i + lane : PN_DATA_FRAGMENTS + PN_LANES * (i - PN_LANE_DATA) + lane;
				word[i] = fragments[j * PN_FRAGMENT + b];
			}
			r = pn_rs_decode(word, PN_LANE_DATA + p, p, lost, f);
			for (i = 0; !r && i < PN_LANE_DATA; i++)
				fragments[(PN_LANES * i + lane) * PN_FRAGMENT + b] = word[i];
		}
	}
	memzero_explicit(word, sizeof(word));
	return r;
}
