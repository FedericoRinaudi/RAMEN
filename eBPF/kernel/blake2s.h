#ifndef __BLAKE2S_H
#define __BLAKE2S_H

#define BLAKE2S_DIGEST_SIZE 32
#define BLAKE2S_KEY_SIZE 32
#define BLAKE2S_BLOCK_SIZE 64
#define MESSAGE_SIZE 32
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memcmp(s1, s2, n) __builtin_memcmp((s1), (s2), (n))

#define ROR32(a, n)   (((a) >> (n)) | ((a) << (32 - (n))))

#define G(a, b, c, d, x, y) \
{ \
   a += b + x; \
   d ^= a; \
   d = ROR32(d, 16); \
   c += d; \
   b ^= c; \
   b = ROR32(b, 12); \
   a += b + y; \
   d ^= a; \
   d = ROR32(d, 8); \
   c += d; \
   b ^= c; \
   b = ROR32(b, 7); \
}

static const __u8 sigma[10][16] =
{
   {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
   {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
   {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
   {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
   {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
   {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
   {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
   {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
   {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
   {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};
 
static const __u32 iv[8] =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};
 

static __always_inline void blake2s_compress(__u32 *m, __u32 *h, __u32 *v)
{

   #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ 
   #pragma unroll
   for(int i = 0; i < 8; i++)
   {
       m[i] = __builtin_bswap32(m[i]); 
   }
   #endif
 
   #pragma unroll
   for(int i = 0; i < 10; i++)
   {
      //The column rounds apply the quarter-round function to the four
      //columns, from left to right
      G(v[0], v[4], v[8],  v[12], m[sigma[i][0]], m[sigma[i][1]]);
      G(v[1], v[5], v[9],  v[13], m[sigma[i][2]], m[sigma[i][3]]);
      G(v[2], v[6], v[10], v[14], m[sigma[i][4]], m[sigma[i][5]]);
      G(v[3], v[7], v[11], v[15], m[sigma[i][6]], m[sigma[i][7]]);
 
      //The diagonal rounds apply the quarter-round function to the top-left,
      //bottom-right diagonal, followed by the pattern shifted one place to
      //the right, for three more quarter-rounds
      G(v[0], v[5], v[10], v[15], m[sigma[i][8]],  m[sigma[i][9]]);
      G(v[1], v[6], v[11], v[12], m[sigma[i][10]], m[sigma[i][11]]);
      G(v[2], v[7], v[8],  v[13], m[sigma[i][12]], m[sigma[i][13]]);
      G(v[3], v[4], v[9],  v[14], m[sigma[i][14]], m[sigma[i][15]]);
   }
 
   #pragma unroll
   for(int i = 0; i < 8; i++)
   {
      h[i] ^= v[i] ^ v[i + 8];
   }
}

static __always_inline void blake2sCompute(const __u8 *key, const __u8 *data, __u32 *digest)
{
   __u32 v[16];
   __u32 m[16];
   digest[0] = 0x6B08C647;
   digest[1] = 0xBB67AE85;
   digest[2] = 0x3C6EF372;
   digest[3] = 0xA54FF53A;
   digest[4] = 0x510E527F;
   digest[5] = 0x9B05688C;
   digest[6] = 0x1F83D9AB;
   digest[7] = 0x5BE0CD19;
   memcpy(m, key, 32);
   memset(m + 8, 0, 32);
   memcpy(v, digest, 32);
   memcpy(v + 8, iv, 32);
   v[12] ^= 64;
   blake2s_compress(m, digest, v);
   memcpy(m, data, 32);
   memset(m + 8, 0, 32);
   memcpy(v, digest, 32);
   memcpy(v + 8, iv, 32);
   v[12] ^= 96;
   v[14] = ~v[14];
   blake2s_compress(m, digest, v);
   #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
   #pragma unroll
   for(int i = 0; i < 8; i++)
   {
       digest[i] = __builtin_bswap32(digest[i]);
   }
   #endif
}
 

#endif // __BLAKE2S_H