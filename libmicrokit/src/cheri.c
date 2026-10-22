/*
 * Copyright 2025, Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <cheri_init_globals.h>

void _start_purecap(void *__capability code_cap, void *__capability data_cap)
{
    cheri_init_globals_3(data_cap, code_cap, code_cap);
}
