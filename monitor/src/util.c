/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 * Copyright 2025, Capabilities Limited.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>

#include "util.h"

#if defined(CONFIG_HAVE_CHERI)
#define CAP_BUFFER_SIZE 85

#if defined(__riscv)
#define __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__ 65536
#define __CHERI_CAP_PERMISSION_CAPABILITY__ 32
#define __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__ 131072
#define __CHERI_CAP_PERMISSION_LOAD_MUTABLE__ 2
#define __CHERI_CAP_PERMISSION_PERMIT_LOAD_CAPABILITY__ 262144
#define __CHERI_CAP_PERMISSION_PERMIT_LOAD__ 262144
#define __CHERI_CAP_PERMISSION_USER_00__ 64
#define __CHERI_CAP_PERMISSION_USER_01__ 128
#define __CHERI_CAP_PERMISSION_USER_02__ 256
#define __CHERI_CAP_PERMISSION_USER_03__ 512
#define __CHERI_CAP_PERMISSION_PERMIT_STORE__ 1
#define __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ 1
#define __CHERI_CAP_PERMISSION_PERMIT_EL__ (1 << 2) /* EL bit */
#define __CHERI_CAP_PERMISSION_PERMIT_SL__ (1 << 3) /* SL bit */
#define __CHERI_CAP_PERMISSION_GLOBAL__ (1 << 4) /* CL bit */

#define CHERI_OTYPE_SENTRY 1
/* cheriTODO: Implement for Morello and other CHERI archs */
#endif
#endif

void putc(uint8_t ch)
{
#if defined(CONFIG_PRINTING)
    seL4_DebugPutChar(ch);
#endif
}

void puts(const char *s)
{
    while (*s) {
        putc(*s);
        s++;
    }
}

static char hexchar(unsigned int v)
{
    return v < 10 ? '0' + v : ('a' - 10) + v;
}

void puthex32(uint32_t val)
{
    char buffer[8 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[8 + 3 - 1] = 0;
    for (unsigned i = 8 + 1; i > 1; i--) {
        buffer[i] = hexchar(val & 0xf);
        val >>= 4;
    }
    puts(buffer);
}

void puthex64(uint64_t val)
{
    char buffer[16 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[16 + 3 - 1] = 0;
    for (unsigned i = 16 + 1; i > 1; i--) {
        buffer[i] = hexchar(val & 0xf);
        val >>= 4;
    }
    puts(buffer);
}

#if defined(CONFIG_HAVE_CHERI)
static inline char *fmt_x(uintmax_t x, char *s, int lower)
{
    for (; x; x>>=4) *--s = hexchar(x&15)|lower;
    return s;
}

void putchericap(seL4_TCB_CheriReadRegister_t cap) {
    char buf[CAP_BUFFER_SIZE];
    char *z = buf + sizeof(buf);
    struct CheriCapMeta cheri_meta = (struct CheriCapMeta) {.words[0] = cap.cheri_meta};
    int tag = CheriCapMeta_get_V(cheri_meta);
    seL4_Word perms = CheriCapMeta_get_AP(cheri_meta);
    if (!tag) {
        // null-dervived capability
        goto value;
    }

    /* Attributes */
    const int type = CheriCapMeta_get_CT(cheri_meta);
#if defined(__riscv)
    /* cheriTODO: fix/implement for Morello when addded */
    const int is_capmode = !CheriCapMeta_get_M(cheri_meta);
#endif
    const int is_sentry = type == CHERI_OTYPE_SENTRY;
    const int is_sealed = 0;

    if (is_sentry) { // sentry
        *--z = ')';
        *--z = 'y';
        *--z = 'r';
        *--z = 't';
        *--z = 'n';
        *--z = 'e';
        *--z = 's';
    } else if (is_sealed) { // any other object type
        *--z = ')';
        *--z = 'd';
        *--z = 'e';
        *--z = 'l';
        *--z = 'a';
        *--z = 'e';
        *--z = 's';
    }

    if (!tag) {
        if (is_sealed) {
            *--z = ',';
        } else {
            *--z = ')';
        }
        *--z = 'd';
        *--z = 'i';
        *--z = 'l';
        *--z = 'a';
        *--z = 'v';
        *--z = 'n';
        *--z = 'i';
    }

    if (!tag || is_sealed || is_sentry) {
        *--z = '(';
        *--z = ' ';
    }

    if (!(perms & __CHERI_CAP_PERMISSION_GLOBAL__)) {
        if (is_sealed || is_sentry) {
            *--z = ',';
        } else {
            *--z = ')';
        }
        *--z = 'l';
        *--z = 'a';
        *--z = 'c';
        *--z = 'o';
        *--z = 'l';
  }

    if (is_sealed || !(perms & __CHERI_CAP_PERMISSION_GLOBAL__)) {
        *--z = '(';
        *--z = ' ';
      }

    if (is_capmode && (perms & __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__)) {
        *--z = ')';
        *--z = 'e';
        *--z = 'd';
        *--z = 'o';
        *--z = 'm';
        *--z = 'p';
        *--z = 'a';
        *--z = 'c';
        *--z = '(';
        *--z = ' ';
    }

    *--z = ']';
    /* Bounds */
    seL4_Word lower_bound = cap.cheri_base;
    seL4_Word upper_bound = lower_bound + cap.cheri_size;
    if ((uintmax_t)upper_bound == 0) {
        *--z = '0';
    } else {
        z = fmt_x(upper_bound, z, 32);
    }
    *--z = 'x';
    *--z = '0';
    *--z = '-';
    if ((uintmax_t)lower_bound == 0) {
        *--z = '0';
    } else {
        z = fmt_x(lower_bound, z, 32);
    }
    *--z = 'x';
    *--z = '0';

    *--z = ',';
    /*
     * Extended Permissions
     * fmt allows for additional formats to be specified and multiple formats to
     * be chained together.
     */
#if defined(__aarch64__)
    if (perms & __CHERI_CAP_PERMISSION_USER3__) {
        *--z = '3';
      }

    if (perms & __CHERI_CAP_PERMISSION_USER2__) {
        *--z = '2';
    }

    if (perms & __CHERI_CAP_PERMISSION_USER1__) {
        *--z = '1';
    }

    if (perms & __CHERI_CAP_PERMISSION_VMEM__) {
        *--z = 'V';
    }
#elif defined(__riscv)
    if (perms & __CHERI_CAP_PERMISSION_USER_03__) {
        *--z = '1';
    }

    if (perms & __CHERI_CAP_PERMISSION_USER_02__) {
        *--z = '1';
    }

    if (perms & __CHERI_CAP_PERMISSION_USER_01__) {
        *--z = '1';
    }

    if (perms & __CHERI_CAP_PERMISSION_USER_00__) {
        *--z = '1';
    }
#endif

#ifdef __ARM_CAP_PERMISSION_COMPARTMENT_ID__
    if (perms & __ARM_CAP_PERMISSION_COMPARTMENT_ID__) {
        *--z = 'C';
    }
#endif


#ifdef __ARM_CAP_PERMISSION_BRANCH_SEALED_PAIR__
    if (perms & __ARM_CAP_PERMISSION_BRANCH_SEALED_PAIR__) {
        *--z = 'I';
    }
#endif

#if defined(__aarch64__)
    if (perms & __CHERI_CAP_PERMISSION_PERMIT_SEAL__) {
        *--z = 's';
    }

    if (perms & __CHERI_CAP_PERMISSION_PERMIT_UNSEAL__) {
        *--z = 'u';
    }

    if (perms & __CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__) {
        *--z = 'L';
    }
#endif

    if (perms & __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__) {
        *--z = 'S';
    }

#ifdef __ARM_CAP_PERMISSION_MUTABLE_LOAD__
    if (perms & __ARM_CAP_PERMISSION_MUTABLE_LOAD__) {
        *--z = 'M';
    }
#endif

#ifdef __CHERI_CAP_PERMISSION_LOAD_MUTABLE__
    if (perms & __CHERI_CAP_PERMISSION_LOAD_MUTABLE__) {
        *--z = 'M';
    }
#endif

    /* Permissions */
    unsigned perms_macros[] =  {
#ifdef __ARM_CAP_PERMISSION_EXECUTIVE__
        __ARM_CAP_PERMISSION_EXECUTIVE__,
#endif
#ifdef __CHERI_CAP_PERMISSION_CAPABILITY__
        __CHERI_CAP_PERMISSION_CAPABILITY__,
#else
        __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__,
        __CHERI_CAP_PERMISSION_PERMIT_LOAD_CAPABILITY__,
#endif
        __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__,
        __CHERI_CAP_PERMISSION_PERMIT_STORE__,
        __CHERI_CAP_PERMISSION_PERMIT_LOAD__};

    char perms_char_rep[] = {
#ifdef __ARM_CAP_PERMISSION_EXECUTIVE__
        'E',
#endif
#ifdef __CHERI_CAP_PERMISSION_CAPABILITY__
        'C',
#else
        'W', 'R',
#endif
        'x', 'w', 'r'};
    for (int i = 0; i < (sizeof(perms_char_rep) / sizeof(perms_char_rep[0])); i++) {
        if ((perms & perms_macros[i]) != 0) {
            *--z = perms_char_rep[i];
        }
    }
    *--z = '[';
    *--z = ' ';
    /* Value */
value:
    if ((uintmax_t)cap.cheri_addr == 0) {
    *--z = '0';
    } else {
        z = fmt_x((uintmax_t)cap.cheri_addr, z, 32);
    }
    *--z = 'x';
    *--z = '0';

    puts(z);
}
#endif

void fail(char *s)
{
    puts("FAIL: ");
    puts(s);
    puts("\n");
    for (;;) {}
}

char *sel4_strerror(seL4_Word err)
{
    switch (err) {
    case seL4_NoError:
        return "seL4_NoError";
    case seL4_InvalidArgument:
        return "seL4_InvalidArgument";
    case seL4_InvalidCapability:
        return "seL4_InvalidCapability";
    case seL4_IllegalOperation:
        return "seL4_IllegalOperation";
    case seL4_RangeError:
        return "seL4_RangeError";
    case seL4_AlignmentError:
        return "seL4_AlignmentError";
    case seL4_FailedLookup:
        return "seL4_FailedLookup";
    case seL4_TruncatedMessage:
        return "seL4_TruncatedMessage";
    case seL4_DeleteFirst:
        return "seL4_DeleteFirst";
    case seL4_RevokeFirst:
        return "seL4_RevokeFirst";
    case seL4_NotEnoughMemory:
        return "seL4_NotEnoughMemory";
    }

    return "<invalid seL4 error>";
}

char *strcpy(char *restrict dst, const char *restrict src)
{
    int i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';

    return dst;
}
