/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
.extern main
#if defined(__CHERI_PURE_CAPABILITY__)
.extern _start_purecap
#endif

.section ".text.start"

.global _start;
.type _start, %function;
_start:
#if defined(__CHERI_PURE_CAPABILITY__)
   /* ca0 and ca1 should hold code and data caps and passed to us on start */
    bl _start_purecap
    /* Make sure after we initialise the captable that
     * we don't leak any powerful capabilities to the C user
     * eg ca0/ca1 that were used to construct the captable.
     * Writing integer registers will clear the capability tags.
     */
#endif
    b main
