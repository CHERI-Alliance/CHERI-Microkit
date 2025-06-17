/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

.extern main
.extern __global_pointer$
#if defined(__CHERI_PURE_CAPABILITY__)
.extern _start_purecap
#endif

.section ".text.start"

.global _start;
.type _start, %function;
_start:
.option push
.option norelax
1:
#if defined(__CHERI_PURE_CAPABILITY__)
   /* ca0 and ca1 should hold code and data caps and passed to us on start */
    call _start_purecap
    /* Make sure after we initialise the captable that
     * we don't leak any powerful capabilities to the C user
     * eg ca0/ca1 that were used to construct the captable.
     * Writing integer registers will clear the capability tags.
     */
    call _reset_regs
    call main
#else
1:  auipc gp, %pcrel_hi(__global_pointer$)
    addi  gp, gp, %pcrel_lo(1b)
.option pop
    j main
#endif

.globl _reset_regs
_reset_regs:
  /* flush the instruction cache */
  fence.i
  /* Reset all registers except ra and sp */
  li tp, 0
  li gp, 0
  li t0, 0
  li t1, 0
  li t2, 0
  li s0, 0
  li s1, 0
  li a0, 0
  li a1, 0
  li a2, 0
  li a3, 0
  li a4, 0
  li a5, 0
  li a6, 0
  li a7, 0
  li s2, 0
  li s3, 0
  li s4, 0
  li s5, 0
  li s6, 0
  li s7, 0
  li s8, 0
  li s9, 0
  li s10, 0
  li s11, 0
  li t3, 0
  li t4, 0
  li t5, 0
  li t6, 0
  ret
