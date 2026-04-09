/*
 * Stream Cipher - OFB and CTR modes
 *
 * Design summary:
 *   - Custom S-box based block cipher core (ChiperCore / ChiperECB)
 *   - S-box is secret: derived from password+salt via Fisher-Yates shuffle
 *   - Key is derived from password+salt using a memory-hard iterative KDF
 *   - OFB mode: keystream = Encrypt(Encrypt(...(IV)...))
 *   - CTR mode: keystream = Encrypt(IV+0), Encrypt(IV+1), ... (recommended)
 *   - Random salt generated per session via OS CSPRNG
 */

// Optimization
#pragma GCC optimize("O3")

#include "manochiper.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

//--- Platform random includes ---
#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #include <bcrypt.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
  #if defined(__linux__)
	#include <sys/syscall.h>
  #endif
#endif


//----- Internal function declarations -----

static inline void ChiperECB(uint64_t *block, const uint64_t *key,
							  const uint8_t *sbox);

static void ChiperNextBlock_OFB(ChiperData *data);
static void ChiperNextBlock_CTR(ChiperData *data);

static void XorAddLooped(void *dst, size_t dst_len,
						 const void *src, size_t src_len);

static int  OSRandomBytes(void *buf, size_t len);
static void GenerateSbox(uint8_t *sbox, ChiperData *data);
static void do_sbox_no_short_cycle(uint8_t *sbox);
static void SecureWipe(void *buf, size_t len);


//----- Base (hardcoded) S-box -----
/*
 * A true random permutation of 0..255 generated from /dev/urandom.
 * Used only as the initial constant for key derivation (salt/seed role).
 * The actual S-box used for encryption is secret and key-derived.
 * Stored doubled (512 bytes) so that sbox[a+b] never needs modulo
 * when a and b are both uint8_t (max sum = 510 < 512).
 */
static const uint8_t base_sbox[512] = {
0xE2, 0x46, 0xCB, 0x0E, 0xB1, 0xB0, 0xB2, 0x73, 0x4E, 0xC9, 0xB5, 0x36, 0x89, 0x98, 0x16, 0xDE,
0x70, 0x8C, 0x1B, 0xEF, 0x60, 0x48, 0x61, 0x7E, 0x4C, 0x72, 0xBF, 0xD6, 0x2A, 0xF4, 0x37, 0x96,
0x4D, 0xE5, 0x7C, 0x21, 0xFD, 0xC6, 0xCC, 0x35, 0x39, 0x47, 0x87, 0x2C, 0x9C, 0x34, 0xDC, 0x84,
0x44, 0x9A, 0x03, 0x8D, 0x66, 0x62, 0xE7, 0x81, 0x5B, 0x57, 0xD9, 0x1D, 0x2E, 0x71, 0x90, 0xA4,
0xBE, 0x55, 0x3A, 0x3D, 0x18, 0x50, 0x24, 0xF9, 0x42, 0x6E, 0x97, 0x2B, 0x58, 0xAF, 0x06, 0xF7,
0xD0, 0xD3, 0xD5, 0x01, 0x8A, 0xB4, 0xA8, 0x1A, 0x67, 0x69, 0x6F, 0xE4, 0x0B, 0x80, 0xA2, 0x3C,
0xC1, 0x4A, 0x41, 0x6A, 0xD8, 0x3F, 0x78, 0xF5, 0x56, 0x9F, 0xE6, 0xF0, 0xA6, 0xA7, 0x5F, 0x02,
0xA9, 0x86, 0x45, 0xBB, 0x51, 0x17, 0xAB, 0xE9, 0xDA, 0x59, 0xF1, 0xBD, 0x8B, 0x09, 0x27, 0xFE,
0x3B, 0xD7, 0xEB, 0x04, 0x8E, 0x93, 0x68, 0x9B, 0xBA, 0x52, 0xF6, 0x30, 0x95, 0x54, 0x5D, 0xC5,
0x92, 0x7D, 0xBC, 0x05, 0x79, 0xEC, 0x64, 0xED, 0xB3, 0xFF, 0x19, 0x9D, 0xA0, 0x99, 0xE1, 0x15,
0x94, 0x9E, 0xEA, 0x07, 0xC2, 0xC4, 0xF8, 0x0F, 0x0D, 0x8F, 0xDD, 0xC7, 0xB9, 0xE3, 0x76, 0xC3,
0x31, 0x5A, 0x6D, 0xCF, 0x26, 0x7F, 0x2F, 0xFB, 0xB7, 0x0A, 0x10, 0xFC, 0x5E, 0x13, 0x77, 0xCA,
0xEE, 0x4B, 0x7A, 0xA1, 0x65, 0x83, 0x22, 0xAA, 0x6B, 0xA3, 0x1E, 0xA5, 0x1C, 0x25, 0xF2, 0xD4,
0xC8, 0x63, 0xD1, 0x0C, 0x00, 0xCE, 0x11, 0xF3, 0xD2, 0x6C, 0x33, 0x20, 0x53, 0xCD, 0x32, 0x14,
0xDF, 0x12, 0x29, 0xFA, 0xC0, 0x3E, 0x23, 0x91, 0xAE, 0x28, 0xAD, 0x4F, 0x38, 0xE8, 0x40, 0x82,
0x7B, 0x1F, 0x2D, 0xAC, 0x49, 0xDB, 0x08, 0x88, 0x5C, 0xB6, 0xB8, 0x43, 0x85, 0x75, 0xE0, 0x74,
/* repeated for speed (index a+b where a,b are uint8_t: max 255+255=510) */
0xE2, 0x46, 0xCB, 0x0E, 0xB1, 0xB0, 0xB2, 0x73, 0x4E, 0xC9, 0xB5, 0x36, 0x89, 0x98, 0x16, 0xDE,
0x70, 0x8C, 0x1B, 0xEF, 0x60, 0x48, 0x61, 0x7E, 0x4C, 0x72, 0xBF, 0xD6, 0x2A, 0xF4, 0x37, 0x96,
0x4D, 0xE5, 0x7C, 0x21, 0xFD, 0xC6, 0xCC, 0x35, 0x39, 0x47, 0x87, 0x2C, 0x9C, 0x34, 0xDC, 0x84,
0x44, 0x9A, 0x03, 0x8D, 0x66, 0x62, 0xE7, 0x81, 0x5B, 0x57, 0xD9, 0x1D, 0x2E, 0x71, 0x90, 0xA4,
0xBE, 0x55, 0x3A, 0x3D, 0x18, 0x50, 0x24, 0xF9, 0x42, 0x6E, 0x97, 0x2B, 0x58, 0xAF, 0x06, 0xF7,
0xD0, 0xD3, 0xD5, 0x01, 0x8A, 0xB4, 0xA8, 0x1A, 0x67, 0x69, 0x6F, 0xE4, 0x0B, 0x80, 0xA2, 0x3C,
0xC1, 0x4A, 0x41, 0x6A, 0xD8, 0x3F, 0x78, 0xF5, 0x56, 0x9F, 0xE6, 0xF0, 0xA6, 0xA7, 0x5F, 0x02,
0xA9, 0x86, 0x45, 0xBB, 0x51, 0x17, 0xAB, 0xE9, 0xDA, 0x59, 0xF1, 0xBD, 0x8B, 0x09, 0x27, 0xFE,
0x3B, 0xD7, 0xEB, 0x04, 0x8E, 0x93, 0x68, 0x9B, 0xBA, 0x52, 0xF6, 0x30, 0x95, 0x54, 0x5D, 0xC5,
0x92, 0x7D, 0xBC, 0x05, 0x79, 0xEC, 0x64, 0xED, 0xB3, 0xFF, 0x19, 0x9D, 0xA0, 0x99, 0xE1, 0x15,
0x94, 0x9E, 0xEA, 0x07, 0xC2, 0xC4, 0xF8, 0x0F, 0x0D, 0x8F, 0xDD, 0xC7, 0xB9, 0xE3, 0x76, 0xC3,
0x31, 0x5A, 0x6D, 0xCF, 0x26, 0x7F, 0x2F, 0xFB, 0xB7, 0x0A, 0x10, 0xFC, 0x5E, 0x13, 0x77, 0xCA,
0xEE, 0x4B, 0x7A, 0xA1, 0x65, 0x83, 0x22, 0xAA, 0x6B, 0xA3, 0x1E, 0xA5, 0x1C, 0x25, 0xF2, 0xD4,
0xC8, 0x63, 0xD1, 0x0C, 0x00, 0xCE, 0x11, 0xF3, 0xD2, 0x6C, 0x33, 0x20, 0x53, 0xCD, 0x32, 0x14,
0xDF, 0x12, 0x29, 0xFA, 0xC0, 0x3E, 0x23, 0x91, 0xAE, 0x28, 0xAD, 0x4F, 0x38, 0xE8, 0x40, 0x82,
0x7B, 0x1F, 0x2D, 0xAC, 0x49, 0xDB, 0x08, 0x88, 0x5C, 0xB6, 0xB8, 0x43, 0x85, 0x75, 0xE0, 0x74
};


//----- Core cipher algorithm -----

/*
 * ChiperCore: two-pass substitution over the whole buffer.
 * A single bit change in any byte causes all bytes to change (full diffusion).
 * Uses the caller-supplied sbox (secret, key-derived).
 * IMPORTANT: n must be > 0, not checked here.
 */
__attribute__((always_inline))
static inline void ChiperCore(uint8_t *b, const size_t n, const uint8_t *sbox)
{
	size_t i;
	for (i = 0; i < n - 1; i++)
		b[i+1] = sbox[ b[i] + b[i+1] ];
	for (i = n - 1; i > 0; i--)
		b[i-1] = sbox[ b[i-1] + b[i] ];
}

/*
 * ChiperECB: encrypt one block with key-wrapping (XOR-Encrypt-XOR).
 * The double XOR prevents known/chosen-plaintext attacks on the raw
 * substitution core.
 */
static inline void ChiperECB(uint64_t *block, const uint64_t *key,
							  const uint8_t *sbox)
{
	size_t i;

	/* Step 1: XOR with key */
	for (i = 0; i < CHIPER_QWORDS; i++)
		block[i] ^= key[i];

	/* Step 2: substitution (full diffusion) */
	ChiperCore((uint8_t *)block, CHIPER_BYTES, sbox);

	/* Step 3: XOR with key again */
	for (i = 0; i < CHIPER_QWORDS; i++)
		block[i] ^= key[i];
}


//----- Keystream block generation -----

/* OFB: next block = Encrypt(previous block) */
static void ChiperNextBlock_OFB(ChiperData *data)
{
	ChiperECB(data->block, data->key, data->sbox);
	data->block_bytepos = 0;
}

/*
 * CTR: next block = Encrypt(counter), then increment counter.
 * Counter is a simple little-endian 256-bit integer.
 */
static void ChiperNextBlock_CTR(ChiperData *data)
{
	/* Copy counter into block, then encrypt it */
	memcpy(data->block, data->counter, CHIPER_BYTES);
	ChiperECB(data->block, data->key, data->sbox);
	data->block_bytepos = 0;

	/* Increment counter as little-endian byte array 
	 * It works on big-endian machine too */
    uint8_t *c = (uint8_t *)data->counter;
    size_t i;
    for (i = 0; i < CHIPER_BYTES; i++)
    {
        c[i]++;
        if (c[i] != 0) break; // break if no carry
    }
}

/* Dispatch the mode */
static inline void ChiperNextBlock(ChiperData *data)
{
	if (data->mode == CHIPER_MODE_CTR)
		ChiperNextBlock_CTR(data);
	else
		ChiperNextBlock_OFB(data);
}


//----- S-box generation -----

/*
 * Rearrange sbox (permutation) into a single 256-element cycle.
 * This guarantees no short cycles: sbox[sbox[...[x]...]] = x
 * only after exactly 256 applications.
 * Works on the first 256 bytes only (call before doubling).
 */
static void do_sbox_no_short_cycle(uint8_t *sbox)
{
	uint8_t sbox_old[256];
	memcpy(sbox_old, sbox, 256);
	size_t i, j;
	j = (size_t)sbox_old[0];
	for (i = 1; i < 256; i++)
	{
		sbox[j] = sbox_old[i];
		j = (size_t)sbox[j];
	}
	sbox[j] = sbox_old[0];
}

/*
 * Fisher-Yates shuffle driven by the cipher keystream.
 * Produces a uniformly distributed random permutation of 0..255.
 * Rejection sampling ensures no modulo bias.
 * After shuffling, applies do_sbox_no_short_cycle() and doubles the table.
 *
 * Prerequisite: data->key must be set, ChiperReset() must have been called
 * so the keystream is ready. The keystream bytes consumed here are separate
 * from the encryption stream (ChiperReset is called again after this).
 */
static void GenerateSbox(uint8_t *sbox, ChiperData *data)
{
	/* Start with identity permutation */
	int i;
	for (i = 0; i < 256; i++)
		sbox[i] = (uint8_t)i;

	/* Fisher-Yates shuffle (from end to beginning) */
	for (i = 255; i > 0; i--)
	{
		/* Unbiased random index in [0..i] using rejection sampling
		 * Naive algorithm j = random(256) % i -> modulo bias problem! */
		uint16_t range = (uint16_t)i + 1;  // [0..i] has i+1 possible values
		uint16_t limit = 256 - (256 % range); // rejection threshold
		uint8_t r;
		do
		{
			ChiperStreamEncode(data, &r, 1);
		} while ((uint16_t)r >= limit);
		uint8_t j = (uint8_t)(r % range);

		/* Swap */
		uint8_t tmp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}

	/* Guarantee single full cycle (no short cycles) */
	do_sbox_no_short_cycle(sbox);

	/* Double the table for the speed trick (index = a+b, max 510) */
	memcpy(sbox + 256, sbox, 256);
}


//----- Key derivation -----

/*
 * Memory-hard iterative KDF.
 * Uses a large working buffer (CHIPER_KDF_MEM bytes) to raise the cost
 * of parallel GPU brute-force attacks.
 * Password is re-injected every iteration so short passwords still
 * influence every round.
 * Returns 0 on success, -1 on malloc failure.
 */
static int DeriveKey(uint64_t *key, const char *psw, const int len,
					 const uint8_t *salt)
{
	size_t obfs_len = CHIPER_KDF_MEM;
	if (obfs_len < 256) obfs_len = 256;

	uint8_t *obfs_vec = (uint8_t *)malloc(obfs_len);
	if (obfs_vec == NULL) return -1;

	size_t plen = 0;
	if (psw != NULL)
		plen = (len > 0) ? (size_t)len : strlen(psw);

	/* Initialize buffer with base_sbox repeated */
	size_t i;
	for (i = 0; i < obfs_len; i++)
		obfs_vec[i] = base_sbox[i % 256];

	/* Mix salt in */
	if (salt != NULL)
		XorAddLooped(obfs_vec, obfs_len, salt, CHIPER_SALT_BYTES);

	/* Mix password in initially */
	if (plen > 0)
		XorAddLooped(obfs_vec, obfs_len, psw, plen);

	/* Iterative mixing */
	int c;
	for (c = 0; c < CHIPER_KDF_ITER; c++)
	{
		/* Re-inject password every round */
		if (plen > 0)
			XorAddLooped(obfs_vec, obfs_len, psw, plen);

		/* Re-inject iteration counter (prevents state cycles) */
		uint32_t counter = (uint32_t)c;
		XorAddLooped(obfs_vec, obfs_len, &counter, sizeof(counter));

		/* Memory-hard mixing step: touches entire buffer */
		ChiperCore(obfs_vec, obfs_len, base_sbox);
	}

	/* Compress to key size (one-way) */
	memset(key, 0, CHIPER_BYTES);
	XorAddLooped(key, CHIPER_BYTES, obfs_vec, obfs_len);

	/* Secure wipe before freeing */
	SecureWipe(obfs_vec, obfs_len);
	free(obfs_vec);

	return 0;
}


//----- Public API -----

/*
 * ChiperInit: derive key and S-box from password + salt, then reset stream.
 *
 * Sequence:
 *   1. Derive key from password+salt (memory-hard KDF)
 *   2. Initialize temporaly the chiper (and the keystream)
 *   3. Generate secret S-box from that keystream (pseudo-random shuffle)
 *   4. Reset the keystream with this S-box, so encryption starts fresh
 */
int ChiperInit(ChiperData *data, const char *psw, const int len,
			   const uint8_t *salt, ChiperMode mode)
{
	if (data == NULL) return -1;
	memset(data, 0, sizeof(ChiperData));
	data->mode = mode;

	/* Step 1: derive key */
	if (DeriveKey(data->key, psw, len, salt) != 0)
		return -1;

	/*
	 * Step 2: initialize temporaly the chiper (and the keystream)
	 * We need a working keystream to drive the S-box shuffle,
	 * but the secret S-box isn't ready yet.
	 * Use base_sbox as initial S-Box - and replace it in Step 3
	 */
	memcpy(data->sbox, base_sbox, 512);

	/* Initialize counter with salt for CTR mode
	 * (gives a unique starting point tied to this session) */
	if (salt != NULL)
		memcpy(data->counter, salt, CHIPER_BYTES);
	else
		memset(data->counter, 0, CHIPER_BYTES);

	/* Prime the block for OFB / CTR */
	memcpy(data->block, base_sbox, CHIPER_BYTES);
	ChiperECB(data->block, data->key, data->sbox);
	data->block_bytepos = 0;

	/* Step 3: generate secret S-box from keystream */
	GenerateSbox(data->sbox, data);

	/* Step 4: reset stream — uses the secret S-box from here on */
	ChiperReset(data);

	return 0;
}

/*
 * ChiperReset: restart the keystream from the beginning.
 * Key and S-box are preserved; only the stream state is reset.
 * In CTR mode the counter is also reset to its initial value (IV = salt-derived).
 */
void ChiperReset(ChiperData *data)
{
	/*
	 * Use the first 256 bytes of the secret S-box as the initial block
	 * This ties the IV to the secret S-box, not a public constant.
	 */
	memcpy(data->block, data->sbox, CHIPER_BYTES);
	ChiperECB(data->block, data->key, data->sbox);
	data->block_bytepos = 0;

	/*
	 * CTR mode: reset counter.
	 * The counter was initialized from the salt in ChiperInit;
	 * we store it in data->counter[0] after encoding with key+sbox
	 * so that the starting point is secret.
	 * Here we reload the initial counter value from the block we just made.
	 */
	if (data->mode == CHIPER_MODE_CTR)
	{
		memcpy(data->counter, data->block, CHIPER_BYTES);
		/* Generate the first real CTR block */
		ChiperNextBlock_CTR(data);
	}
}

/*
 * ChiperStreamEncode: encrypt or decrypt a buffer in-place.
 * Both operations are identical (XOR stream cipher).
 */
void ChiperStreamEncode(ChiperData *data, void *buffer, size_t len)
{
	size_t pos = 0;
	uint8_t *buf = (uint8_t *)buffer;

	while (pos < len)
	{
		/* Generate next block if current one is exhausted */
		if (data->block_bytepos >= CHIPER_BYTES)
			ChiperNextBlock(data);

		/* Fast path: full-block XOR when block is fresh and enough data remains */
		if (data->block_bytepos == 0)
		{
			while (pos + CHIPER_BYTES <= len)
			{
				const uint8_t *block_b = (const uint8_t *)data->block;
				size_t i;
				for (i = 0; i < CHIPER_BYTES; i++)
					buf[pos + i] ^= block_b[i];
				pos += CHIPER_BYTES;
				ChiperNextBlock(data);
			}
		}

		/* Slow path: byte-by-byte for partial block or end of buffer */
		const uint8_t *block_b = (const uint8_t *)data->block;
		size_t blockpos = data->block_bytepos;
		while (pos < len && blockpos < CHIPER_BYTES)
		{
			buf[pos++] ^= block_b[blockpos++];
		}
		data->block_bytepos = blockpos;
	}
}

/*
 * ChiperPasswordScramble
 *   Scramble (deterministically) password string
 */
void ChiperPasswordScramble(char *psw)
{
	const size_t len = strlen(psw);
	ChiperCore(psw, len, base_sbox);
	char * psw_copy = malloc(len);
	if (psw_copy == NULL) return;
	memcpy(psw_copy, psw, len);
	ChiperCore(psw, len, base_sbox);
	XorAddLooped(psw, len, psw_copy, len);
	SecureWipe(psw_copy, len);
	free(psw_copy);
}


//----- OS random number generation -----

/*
 * OSRandomBytes: fill buf with len cryptographically random bytes.
 * Uses the best available OS source on each platform.
 * Returns 0 on success, -1 on failure.
 * NEVER falls back to weak sources — fails loudly instead.
 */
int ChiperGenerateSalt(uint8_t *salt)
{
	return OSRandomBytes(salt, CHIPER_SALT_BYTES);
}

static int OSRandomBytes(void *buf, size_t len)
{
	if (buf == NULL || len == 0) return -1;

#if defined(_WIN32) || defined(_WIN64)
	/*--- Windows: BCryptGenRandom (Vista+, cryptographically strong) ---*/
	NTSTATUS status = BCryptGenRandom(
		NULL,
		(PUCHAR)buf,
		(ULONG)len,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);
	return (status == 0) ? 0 : -1;

#elif defined(__linux__)
	/*--- Linux: getrandom() syscall (kernel 3.17+) ---*/
	/*   Blocks at early boot until entropy pool is seeded (flag=0).   */
	/*   This is correct behaviour for key/salt generation.            */
  #if defined(SYS_getrandom)
	ssize_t ret = syscall(SYS_getrandom, buf, len, 0);
	if (ret == (ssize_t)len) return 0;
  #endif

	/*--- Linux fallback: /dev/urandom ---*/
	{
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0)
		{
			ssize_t ret = read(fd, buf, len);
			close(fd);
			if (ret == (ssize_t)len) return 0;
		}
	}
	return -1;

#elif defined(__APPLE__) || defined(__FreeBSD__) || \
	  defined(__OpenBSD__)  || defined(__NetBSD__)
	/*--- macOS / BSD: /dev/urandom (equivalent to /dev/random here) ---*/
	{
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0)
		{
			ssize_t ret = read(fd, buf, len);
			close(fd);
			if (ret == (ssize_t)len) return 0;
		}
	}
	return -1;

#else
	/*--- Unknown platform: refuse to continue ---*/
	#warning "No cryptographic random source known for this platform!"
	(void)buf; (void)len;
	return -1;
#endif
}


//----- Helper functions -----

#define MAX(a,b) (((a)>(b))?(a):(b))

/*
 * XorAddLooped: XOR src into dst, looping the shorter one.
 * Handles any combination of lengths.
 */
static void XorAddLooped(void *dst, const size_t dst_len,
						 const void *src, const size_t src_len)
{
	if (dst_len == 0 || src_len == 0) return;

	unsigned char *dstb = (unsigned char *)dst;
	const unsigned char *srcb = (const unsigned char *)src;
	size_t dst_pos = 0;
	size_t src_pos = 0;
	size_t maxlen = MAX(dst_len, src_len);
	size_t i;
	for (i = 0; i < maxlen; i++)
	{
		dstb[dst_pos] ^= srcb[src_pos];
		dst_pos = (dst_pos + 1) % dst_len;
		src_pos = (src_pos + 1) % src_len;
	}
}

/*
 * SecureWipe: zero memory in a way the compiler cannot optimize away.
 * Use instead of memset() for sensitive data before free().
 */
static void SecureWipe(void *buf, size_t len)
{
#if defined(_WIN32) || defined(_WIN64)
	SecureZeroMemory(buf, len);
#else
	/* Portable fallback via volatile pointer */
	volatile uint8_t *p = (volatile uint8_t *)buf;
	size_t i;
	for (i = 0; i < len; i++) p[i] = 0;
#endif
}
