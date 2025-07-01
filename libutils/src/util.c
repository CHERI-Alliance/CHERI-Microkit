/*
 * Copyright 2022, UNSW (ABN 57 195 873 179)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <microkit.h>
#include <sel4/assert.h>

#ifdef __CHERI_PURE_CAPABILITY__
typedef __intcap_t BLOCK_TYPE;
#else
typedef long BLOCK_TYPE;
#endif

/* Nonzero if either X or Y is not aligned on a "BLOCK_TYPE" boundary.  */
#define UNALIGNED(X, Y) \
  (((long)X & (sizeof (BLOCK_TYPE) - 1)) | ((long)Y & (sizeof (BLOCK_TYPE) - 1)))

/* How many bytes are copied each iteration of the 4X unrolled loop.  */
#define BIGBLOCKSIZE    (sizeof (BLOCK_TYPE) << 2)

/* How many bytes are copied each iteration of the word copy loop.  */
#define LITTLEBLOCKSIZE (sizeof (BLOCK_TYPE))

/* Threshhold for punting to the byte copier.  */
#if __CHERI_PURE_CAPABILITY__
#define TOO_SMALL(LEN)  ((LEN) < LITTLEBLOCKSIZE)
#else
#define TOO_SMALL(LEN)  ((LEN) < BIGBLOCKSIZE)
#endif

/*
 * memzero needs a custom type that allows us to use a word
 * that has the aliasing properties of a char.
 */
typedef unsigned long __attribute__((__may_alias__)) ulong_alias;

/* This is required to use the printf library we brought in, it is
   simply for convenience since there's a lot of logging/debug printing
   in the VMM. */
void _putchar(char character)
{
    microkit_dbg_putc(character);
}

void memzero(void *s, unsigned long n)
{
    unsigned char *p = s;

    /* Ensure alignment constraints are met. */
    seL4_Assert((unsigned long)s % sizeof(unsigned long) == 0);
    seL4_Assert(n % sizeof(unsigned long) == 0);

    /* Write out words. */
    while (n != 0) {
        *(ulong_alias *)p = 0;
        p += sizeof(ulong_alias);
        n -= sizeof(ulong_alias);
    }
}

void *
memcpy (void *__restrict dst0,
    const void *__restrict src0,
    unsigned long len0)
{
    char *dst = dst0;
    const char *src = src0;
    BLOCK_TYPE *aligned_dst;
    const BLOCK_TYPE *aligned_src;

    /* If the size is small, or either SRC or DST is unaligned,
    then punt into the byte copy loop.  This should be rare.  */
    if (!TOO_SMALL(len0) && !UNALIGNED (src, dst))
    {
        aligned_dst = (BLOCK_TYPE*)dst;
        aligned_src = (BLOCK_TYPE*)src;

        /* Copy 4X BLOCK_TYPE words at a time if possible.  */
        while (len0 >= BIGBLOCKSIZE)
        {
            *aligned_dst++ = *aligned_src++;
            *aligned_dst++ = *aligned_src++;
            *aligned_dst++ = *aligned_src++;
            *aligned_dst++ = *aligned_src++;
            len0 -= BIGBLOCKSIZE;
        }

        /* Copy one BLOCK_TYPE word at a time if possible.  */
        while (len0 >= LITTLEBLOCKSIZE)
        {
            *aligned_dst++ = *aligned_src++;
            len0 -= LITTLEBLOCKSIZE;
        }

        /* Pick up any residual with a byte copier.  */
        dst = (char*)aligned_dst;
        src = (char*)aligned_src;
    }

    while (len0--)
    *dst++ = *src++;

    return dst0;
}

void *memset(void *s, unsigned long c, unsigned long n)
{
    unsigned char *p;

    /*
     * If we are only writing zeros and we are word aligned, we can
     * use the optimized 'memzero' function.
     */
    if (c == 0 && ((unsigned long)s % sizeof(unsigned long)) == 0 && (n % sizeof(unsigned long)) == 0) {
        memzero(s, n);
    } else {
        /* Otherwise, we use a slower, simple memset. */
        for (p = (unsigned char *)s; n > 0; n--, p++) {
            *p = (unsigned char)c;
        }
    }

    return s;
}

 __attribute__ ((__noreturn__))
void __assert_func(const char *file, int line, const char *function, const char *str)
{
    microkit_dbg_puts("assert failed: ");
    microkit_dbg_puts(str);
    microkit_dbg_puts(" ");
    microkit_dbg_puts(file);
    microkit_dbg_puts(" ");
    microkit_dbg_puts(function);
    microkit_dbg_puts("\n");
    while (1) {}
}
