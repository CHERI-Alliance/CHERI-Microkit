/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 * Copyright 2025, Capabilities Limited.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The Microkit Monitor.
 *
 * The monitor is the initial task in a Microkit system.
 *
 * The monitor fulfills two purposes:
 *
 *   1. creating the initial state of the system.
 *   2. acting as the fault handler for for protection domains.
 *
 * Initialisation is performed by executing a number of kernel
 * invocations to create and configure kernel objects.
 *
 * The specific invocations to make are configured by the build
 * tool; the monitor simply reads a data structure to execute
 * each invocation one at a time.
 *
 * The process occurs in a two step manner. The first bootstrap
 * step execute the `bootstrap_invocations` only. The purpose
 * of this bootstrap is to get the system to the point for the
 * `system_invocations` is mapped into the monitors address space.
 * Once this occurs it is possible for the monitor to switch to
 * executing invocation from this second data structure.
 *
 * The motivation for this design is to keep both the initial
 * task image and the initial CNode as small, fixed size entities.
 *
 * Fixed size allows both kernel and monitor to avoid unnecessary
 * recompilation for different system configurations. Keeping things
 * small optimizes overall memory usage.
 *
 *
 */

/*
 * Why this you may ask? Well, the seL4 headers depend on
 * a global `__sel4_ipc_buffer` which is a pointer to the
 * thread's IPC buffer. Which is reasonable enough, passing
 * that explicitly to every function would be annoying.
 *
 * The seL4 headers make this global a thread-local global,
 * which is also reasonable, considering it applies to a
 * specific thread! But, for our purposes we don't have threads!
 *
 * Thread local storage is painful and annoying to configure.
 * We'd really rather NOT use thread local storage (especially
 * consider we never have more than one thread in a Vspace)
 *
 * So, by defining __thread to be empty it means the variable
 * becomes a true global rather than thread local storage
 * variable, which means, we don't need to waste a bunch
 * of effort and complexity on thread local storage implementation.
 */
#define __thread

#include <stdbool.h>
#include <stdint.h>
#include <sel4/sel4.h>

#include "util.h"
#include "debug.h"

#define MAX_VMS 64
#define MAX_PDS 64
#define MAX_NAME_LEN 64

#define MAX_UNTYPED_REGIONS 256

/* Max words available for bootstrap invocations.
 *
 * Only a small number of syscalls is required to
 * get to the point where the main syscalls data
 * is mapped in, so we keep this small.
 *
 * FIXME: This can be smaller once compression is enabled.
 */
#define BOOTSTRAP_INVOCATION_DATA_SIZE 150

seL4_IPCBuffer *__sel4_ipc_buffer;

char _stack[4096];

char pd_names[MAX_PDS][MAX_NAME_LEN];
seL4_Word pd_names_len;
char vm_names[MAX_VMS][MAX_NAME_LEN] __attribute__((unused));
seL4_Word vm_names_len;

seL4_Word fault_ep;
seL4_Word reply;
seL4_Word pd_tcbs[MAX_PDS];
seL4_Word vm_tcbs[MAX_VMS];
seL4_Word scheduling_contexts[MAX_PDS];
seL4_Word notification_caps[MAX_PDS];

/* For reporting potential stack overflows, keep track of the stack regions for each PD. */
seL4_Word pd_stack_addrs[MAX_PDS];

struct region {
    uintptr_t paddr;
    uintptr_t size_bits;
    uintptr_t is_device; /*FIXME: should back size_bits / is_device */
};

struct untyped_info {
    seL4_Word cap_start;
    seL4_Word cap_end;
    struct region regions[MAX_UNTYPED_REGIONS];
};

seL4_Word bootstrap_invocation_count;
seL4_Word bootstrap_invocation_data[BOOTSTRAP_INVOCATION_DATA_SIZE];

seL4_Word system_invocation_count;
seL4_Word *system_invocation_data = (void *)0x80000000;

struct untyped_info untyped_info;

void dump_untyped_info()
{
    puts("\nUntyped Info Expected Memory Ranges\n");
    seL4_Word start = untyped_info.regions[0].paddr;
    seL4_Word end = start + (1ULL << untyped_info.regions[0].size_bits);
    seL4_Word is_device = untyped_info.regions[0].is_device;
    for (int i = 1; i < untyped_info.cap_end - untyped_info.cap_start; i++) {
        if (untyped_info.regions[i].paddr != end || untyped_info.regions[i].is_device != is_device) {
            puts("                                     paddr: ");
            puthex64(start);
            puts(" - ");
            puthex64(end);
            puts(" (");
            puts(is_device ? "device" : "normal");
            puts(")\n");
            start = untyped_info.regions[i].paddr;
            end = start + (1ULL << untyped_info.regions[i].size_bits);
            is_device = untyped_info.regions[i].is_device;
        } else {
            end += (1ULL << untyped_info.regions[i].size_bits);
        }
    }
    puts("                                     paddr: ");
    puthex64(start);
    puts(" - ");
    puthex64(end);
    puts(" (");
    puts(is_device ? "device" : "normal");
    puts(")\n");
}

/*
 * Convert the fault status register given by the kernel into a string describing
 * what fault happened. The FSR is the 'scause' register.
 */
#ifdef ARCH_riscv64
#if defined(CONFIG_HAVE_CHERI)
static char *riscv_fsr_cheri_type_to_string(seL4_Word cheri_type)
{
    switch (cheri_type) {
        case 0:
            return "CHERI instruction fetch fault";
        case 1:
            return "CHERI data fault due to load, store or AMO";
        case 2:
            return "CHERI jump or branch fault";
        default:
            return "Unexpected CHERI fault type";
    }
}
#endif
static char *riscv_fsr_to_string(seL4_Word fsr)
{
#if defined(CONFIG_HAVE_CHERI)
    if ((fsr >> 11) & 1) {
        switch (fsr & 0xf) {
            case 0:
                return "Tag violation";
            case 1:
                return "Seal violation";
            case 2:
                return "Permission violation";
            case 3:
                return "Invalid address violation";
            case 4:
                return "Bounds violation";
            default:
                return "Unexpected CHERI fault";
        }
    }
#endif
    switch (fsr) {
    case 0:
        return "Instruction address misaligned";
    case 1:
        return "Instruction access fault";
    case 2:
        return "Illegal instruction";
    case 3:
        return "Breakpoint";
    case 4:
        return "Load address misaligned";
    case 5:
        return "Load access fault";
    case 6:
        return "Store/AMO address misaligned";
    case 7:
        return "Store/AMO access fault";
    case 8:
        return "Environment call from U-mode";
    case 9:
        return "Environment call from S-mode";
    case 12:
        return "Instruction page fault";
    case 13:
        return "Load page fault";
    case 15:
        return "Store/AMO page fault";
    case 18:
        return "Software check";
    case 19:
        return "Hardware error";
    default:
        return "<Unexpected FSR>";
    }
}
#endif

#ifdef ARCH_aarch64
static char *ec_to_string(uintptr_t ec)
{
    switch (ec) {
    case 0:
        return "Unknown reason";
    case 1:
        return "Trapped WFI or WFE instruction execution";
    case 3:
        return "Trapped MCR or MRC access with (coproc==0b1111) this is not reported using EC 0b000000";
    case 4:
        return "Trapped MCRR or MRRC access with (coproc==0b1111) this is not reported using EC 0b000000";
    case 5:
        return "Trapped MCR or MRC access with (coproc==0b1110)";
    case 6:
        return "Trapped LDC or STC access";
    case 7:
        return "Access to SVC, Advanced SIMD or floating-point functionality trapped";
    case 12:
        return "Trapped MRRC access with (coproc==0b1110)";
    case 13:
        return "Branch Target Exception";
    case 17:
        return "SVC instruction execution in AArch32 state";
    case 21:
        return "SVC instruction execution in AArch64 state";
    case 24:
        return "Trapped MSR, MRS or System instruction exuection in AArch64 state, this is not reported using EC 0xb000000, 0b000001 or 0b000111";
    case 25:
        return "Access to SVE functionality trapped";
    case 28:
        return "Exception from a Pointer Authentication instruction authentication failure";
    case 32:
        return "Instruction Abort from a lower Exception level";
    case 33:
        return "Instruction Abort taken without a change in Exception level";
    case 34:
        return "PC alignment fault exception";
    case 36:
        return "Data Abort from a lower Exception level";
    case 37:
        return "Data Abort taken without a change in Exception level";
    case 38:
        return "SP alignment faultr exception";
    case 40:
        return "Trapped floating-point exception taken from AArch32 state";
    case 44:
        return "Trapped floating-point exception taken from AArch64 state";
    case 47:
        return "SError interrupt";
    case 48:
        return "Breakpoint exception from a lower Exception level";
    case 49:
        return "Breakpoint exception taken without a change in Exception level";
    case 50:
        return "Software Step exception from a lower Exception level";
    case 51:
        return "Software Step exception taken without a change in Exception level";
    case 52:
        return "Watchpoint exception from a lower Exception level";
    case 53:
        return "Watchpoint exception taken without a change in Exception level";
    case 56:
        return "BKPT instruction execution in AArch32 state";
    case 60:
        return "BRK instruction execution in AArch64 state";
    }
    return "<invalid EC>";
}

static char *data_abort_dfsc_to_string(uintptr_t dfsc)
{
    switch (dfsc) {
    case 0x00:
        return "address size fault, level 0";
    case 0x01:
        return "address size fault, level 1";
    case 0x02:
        return "address size fault, level 2";
    case 0x03:
        return "address size fault, level 3";
    case 0x04:
        return "translation fault, level 0";
    case 0x05:
        return "translation fault, level 1";
    case 0x06:
        return "translation fault, level 2";
    case 0x07:
        return "translation fault, level 3";
    case 0x09:
        return "access flag fault, level 1";
    case 0x0a:
        return "access flag fault, level 2";
    case 0x0b:
        return "access flag fault, level 3";
    case 0x0d:
        return "permission fault, level 1";
    case 0x0e:
        return "permission fault, level 2";
    case 0x0f:
        return "permission fault, level 3";
    case 0x10:
        return "synchronuos external abort";
    case 0x11:
        return "synchronous tag check fault";
    case 0x14:
        return "synchronous external abort, level 0";
    case 0x15:
        return "synchronous external abort, level 1";
    case 0x16:
        return "synchronous external abort, level 2";
    case 0x17:
        return "synchronous external abort, level 3";
    case 0x18:
        return "syncrhonous partity or ECC error";
    case 0x1c:
        return "syncrhonous partity or ECC error, level 0";
    case 0x1d:
        return "syncrhonous partity or ECC error, level 1";
    case 0x1e:
        return "syncrhonous partity or ECC error, level 2";
    case 0x1f:
        return "syncrhonous partity or ECC error, level 3";
    case 0x21:
        return "alignment fault";
    case 0x30:
        return "tlb conflict abort";
    case 0x31:
        return "unsupported atomic hardware update fault";
    }
    return "<unexpected DFSC>";
}
#endif

/* UBSAN decoding related functionality */
#define UBSAN_ARM64_BRK_IMM 0x5500
#define UBSAN_ARM64_BRK_MASK 0x00ff
#define ESR_COMMENT_MASK ((1 << 16) - 1)
#define ARM64_BRK_EC 60

/*
 * ABI defined by Clang's UBSAN enum SanitizerHandler:
 * https://github.com/llvm/llvm-project/blob/release/16.x/clang/lib/CodeGen/CodeGenFunction.h#L113
 */
enum UBSAN_CHECKS {
    UBSAN_ADD_OVERFLOW,
    UBSAN_BUILTIN_UNREACHABLE,
    UBSAN_CFI_CHECK_FAIL,
    UBSAN_DIVREM_OVERFLOW,
    UBSAN_DYNAMIC_TYPE_CACHE_MISS,
    UBSAN_FLOAT_CAST_OVERFLOW,
    UBSAN_FUNCTION_TYPE_MISMATCH,
    UBSAN_IMPLICIT_CONVERSION,
    UBSAN_INVALID_BUILTIN,
    UBSAN_INVALID_OBJC_CAST,
    UBSAN_LOAD_INVALID_VALUE,
    UBSAN_MISSING_RETURN,
    UBSAN_MUL_OVERFLOW,
    UBSAN_NEGATE_OVERFLOW,
    UBSAN_NULLABILITY_ARG,
    UBSAN_NULLABILITY_RETURN,
    UBSAN_NONNULL_ARG,
    UBSAN_NONNULL_RETURN,
    UBSAN_OUT_OF_BOUNDS,
    UBSAN_POINTER_OVERFLOW,
    UBSAN_SHIFT_OUT_OF_BOUNDS,
    UBSAN_SUB_OVERFLOW,
    UBSAN_TYPE_MISMATCH,
    UBSAN_ALIGNMENT_ASSUMPTION,
    UBSAN_VLA_BOUND_NOT_POSITIVE,
};

#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
static char *usban_code_to_string(seL4_Word code)
{
    switch (code) {
    case UBSAN_ADD_OVERFLOW:
        return "add overflow";
    case UBSAN_BUILTIN_UNREACHABLE:
        return "builtin unreachable";
    case UBSAN_CFI_CHECK_FAIL:
        return "control-flow-integrity check fail";
    case UBSAN_DIVREM_OVERFLOW:
        return "division remainder overflow";
    case UBSAN_DYNAMIC_TYPE_CACHE_MISS:
        return "dynamic type cache miss";
    case UBSAN_FLOAT_CAST_OVERFLOW:
        return "float case overflow";
    case UBSAN_FUNCTION_TYPE_MISMATCH:
        return "function type mismatch";
    case UBSAN_IMPLICIT_CONVERSION:
        return "implicit conversion";
    case UBSAN_INVALID_BUILTIN:
        return "invalid builtin";
    case UBSAN_INVALID_OBJC_CAST:
        return "invalid objc cast";
    case UBSAN_LOAD_INVALID_VALUE:
        return "load invalid value";
    case UBSAN_MISSING_RETURN:
        return "missing return";
    case UBSAN_MUL_OVERFLOW:
        return "multiplication overflow";
    case UBSAN_NEGATE_OVERFLOW:
        return "negate overflow";
    case UBSAN_NULLABILITY_ARG:
        return "nullability argument";
    case UBSAN_NULLABILITY_RETURN:
        return "nullability return";
    case UBSAN_NONNULL_ARG:
        return "non-null argument";
    case UBSAN_NONNULL_RETURN:
        return "non-null return";
    case UBSAN_OUT_OF_BOUNDS:
        return "out of bounds access";
    case UBSAN_POINTER_OVERFLOW:
        return "pointer overflow";
    case UBSAN_SHIFT_OUT_OF_BOUNDS:
        return "shift out of bounds";
    case UBSAN_SUB_OVERFLOW:
        return "subtraction overflow";
    case UBSAN_TYPE_MISMATCH:
        return "type mismatch";
    case UBSAN_ALIGNMENT_ASSUMPTION:
        return "alignment assumption";
    case UBSAN_VLA_BOUND_NOT_POSITIVE:
        return "variable-length-array bound not positive";
    default:
        return "unknown reason";
    }
}
#endif

static bool check_untypeds_match(seL4_BootInfo *bi)
{
    /* Check that untypeds list generate from build matches the kernel */
    if (untyped_info.cap_start != bi->untyped.start) {
        puts("MON|ERROR: cap start mismatch. Expected cap start: ");
        puthex32(untyped_info.cap_start);
        puts("  boot info cap start: ");
        puthex32(bi->untyped.start);
        puts("\n");
        puts("cap start mismatch");
        return false;
    }

    if (untyped_info.cap_end != bi->untyped.end) {
        puts("MON|ERROR: cap end mismatch. Expected cap end: ");
        puthex32(untyped_info.cap_end);
        puts("  boot info cap end: ");
        puthex32(bi->untyped.end);
        puts("\n");
        puts("cap end mismatch");
        return false;
    }

    for (unsigned i = 0; i < untyped_info.cap_end - untyped_info.cap_start; i++) {
        if (untyped_info.regions[i].paddr != bi->untypedList[i].paddr) {
            puts("MON|ERROR: paddr mismatch for untyped region: ");
            puthex32(i);
            puts("  expected paddr: ");
            puthex64(untyped_info.regions[i].paddr);
            puts("  boot info paddr: ");
            puthex64(bi->untypedList[i].paddr);
            puts("\n");
            puts("paddr mismatch");
            return false;
        }
        if (untyped_info.regions[i].size_bits != bi->untypedList[i].sizeBits) {
            puts("MON|ERROR: size_bits mismatch for untyped region: ");
            puthex32(i);
            puts("  expected size_bits: ");
            puthex32(untyped_info.regions[i].size_bits);
            puts("  boot info size_bits: ");
            puthex32(bi->untypedList[i].sizeBits);
            puts("\n");
            puts("size_bits mismatch");
            return false;
        }
        if (untyped_info.regions[i].is_device != bi->untypedList[i].isDevice) {
            puts("MON|ERROR: is_device mismatch for untyped region: ");
            puthex32(i);
            puts("  expected is_device: ");
            puthex32(untyped_info.regions[i].is_device);
            puts("  boot info is_device: ");
            puthex32(bi->untypedList[i].isDevice);
            puts("\n");
            puts("is_device mismatch");
            return false;
        }
    }

    puts("MON|INFO: bootinfo untyped list matches expected list\n");

    return true;
}

static unsigned perform_invocation(seL4_Word *invocation_data, unsigned offset, unsigned idx)
{
    seL4_MessageInfo_t tag, out_tag;
    seL4_Error result;
    seL4_Word mr0;
    seL4_Word mr1;
    seL4_Word mr2;
    seL4_Word mr3;
    seL4_Word service;
    seL4_Word service_incr;
    seL4_Word cmd = invocation_data[offset];
    seL4_Word iterations = (cmd >> 32) + 1;
    seL4_Word tag0 = cmd & 0xffffffffULL;
    unsigned int cap_offset, cap_incr_offset, cap_count;
    unsigned int mr_offset, mr_incr_offset, mr_count;
    unsigned int next_offset;

    tag.words[0] = tag0;
    service = invocation_data[offset + 1];
    cap_count = seL4_MessageInfo_get_extraCaps(tag);
    mr_count = seL4_MessageInfo_get_length(tag);

#if 0
    puts("Doing invocation: ");
    puthex32(idx);
    puts(" cap count: ");
    puthex32(cap_count);
    puts(" MR count: ");
    puthex32(mr_count);
    puts("\n");
#endif

    cap_offset = offset + 2;
    mr_offset = cap_offset + cap_count;
    if (iterations > 1) {
        service_incr = invocation_data[mr_offset + mr_count];
        cap_incr_offset = mr_offset + mr_count + 1;
        mr_incr_offset = cap_incr_offset + cap_count;
        next_offset = mr_incr_offset + mr_count;
    } else {
        next_offset = mr_offset + mr_count;
    }

    if (seL4_MessageInfo_get_capsUnwrapped(tag) != 0) {
        fail("kernel invocation should never have unwrapped caps");
    }

    for (unsigned i = 0; i < iterations; i++) {
#if 0
        puts("Preparing invocation:\n");
#endif
        /* Set all the caps */
        seL4_Word call_service = service;
        if (i > 0) {
            call_service += service_incr * i;
        }
        for (unsigned j = 0; j < cap_count; j++) {
            seL4_Word cap = invocation_data[cap_offset + j];
            if (i > 0) {
                cap += invocation_data[cap_incr_offset + j] * i;
            }
#if 0
            puts("   SetCap: ");
            puthex32(j);
            puts(" ");
            puthex64(cap);
            puts("\n");
#endif
            seL4_SetCap(j, cap);
        }

        for (unsigned j = 0; j < mr_count; j++) {
            seL4_Word mr = invocation_data[mr_offset + j];
            if (i > 0) {
                mr += invocation_data[mr_incr_offset + j] * i;
            }
#if 0
            puts("   SetMR: ");
            puthex32(j);
            puts(" ");
            puthex64(mr);
            puts("\n");
#endif
            switch (j) {
            case 0:
                mr0 = mr;
                break;
            case 1:
                mr1 = mr;
                break;
            case 2:
                mr2 = mr;
                break;
            case 3:
                mr3 = mr;
                break;
            default:
                seL4_SetMR(j, mr);
                break;
            }
        }

        out_tag = seL4_CallWithMRs(call_service, tag, &mr0, &mr1, &mr2, &mr3);
        result = (seL4_Error) seL4_MessageInfo_get_label(out_tag);
        if (result != seL4_NoError) {
            puts("ERROR: ");
            puthex64(result);
            puts(" ");
            puts(sel4_strerror(result));
            puts("  invocation idx: ");
            puthex32(idx);
            puts(".");
            puthex32(i);
            puts("\n");
            fail("invocation error");
        }
#if 0
        puts("Done invocation: ");
        puthex32(idx);
        puts(".");
        puthex32(i);
        puts("\n");
#endif
    }
    return next_offset;
}

static void print_tcb_registers(seL4_UserContext *regs, seL4_Word tcb_cap)
{
#if defined(ARCH_riscv64)
    puts("Registers: \n");
#if defined(CONFIG_HAVE_CHERI)
    int reg_idx = 0;

    puts("ddc : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, 35));
    puts("\n");
    puts("pcc : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cra : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("csp : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cgp : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs0 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs1 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs2 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs3 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs4 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs5 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs6 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs7 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs8 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs9 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs10 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("cs11 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca0 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca1 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca2 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca3 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca4 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca5 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca6 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ca7 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct0 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct1 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct2 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct3 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct4 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct5 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ct6 : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
    puts("ctp : ");
    putchericap(seL4_TCB_CheriReadRegister(tcb_cap, reg_idx++));
    puts("\n");
#else
    puts("pc : ");
    puthex64(regs->pc);
    puts("\n");
    puts("ra : ");
    puthex64(regs->ra);
    puts("\n");
    puts("s0 : ");
    puthex64(regs->s0);
    puts("\n");
    puts("s1 : ");
    puthex64(regs->s1);
    puts("\n");
    puts("s2 : ");
    puthex64(regs->s2);
    puts("\n");
    puts("s3 : ");
    puthex64(regs->s3);
    puts("\n");
    puts("s4 : ");
    puthex64(regs->s4);
    puts("\n");
    puts("s5 : ");
    puthex64(regs->s5);
    puts("\n");
    puts("s6 : ");
    puthex64(regs->s6);
    puts("\n");
    puts("s7 : ");
    puthex64(regs->s7);
    puts("\n");
    puts("s8 : ");
    puthex64(regs->s8);
    puts("\n");
    puts("s9 : ");
    puthex64(regs->s9);
    puts("\n");
    puts("s10 : ");
    puthex64(regs->s10);
    puts("\n");
    puts("s11 : ");
    puthex64(regs->s11);
    puts("\n");
    puts("a0 : ");
    puthex64(regs->a0);
    puts("\n");
    puts("a1 : ");
    puthex64(regs->a1);
    puts("\n");
    puts("a2 : ");
    puthex64(regs->a2);
    puts("\n");
    puts("a3 : ");
    puthex64(regs->a3);
    puts("\n");
    puts("a4 : ");
    puthex64(regs->a4);
    puts("\n");
    puts("a5 : ");
    puthex64(regs->a5);
    puts("\n");
    puts("a6 : ");
    puthex64(regs->a6);
    puts("\n");
    puts("t0 : ");
    puthex64(regs->t0);
    puts("\n");
    puts("t1 : ");
    puthex64(regs->t1);
    puts("\n");
    puts("t2 : ");
    puthex64(regs->t2);
    puts("\n");
    puts("t3 : ");
    puthex64(regs->t3);
    puts("\n");
    puts("t4 : ");
    puthex64(regs->t4);
    puts("\n");
    puts("t5 : ");
    puthex64(regs->t5);
    puts("\n");
    puts("t6 : ");
    puthex64(regs->t6);
    puts("\n");
    puts("tp : ");
    puthex64(regs->tp);
    puts("\n");
#endif
#elif defined(ARCH_aarch64)
    puts("Registers: \n");
    puts("pc : ");
    puthex64(regs->pc);
    puts("\n");
    puts("sp: ");
    puthex64(regs->sp);
    puts("\n");
    puts("spsr : ");
    puthex64(regs->spsr);
    puts("\n");
    puts("x0 : ");
    puthex64(regs->x0);
    puts("\n");
    puts("x1 : ");
    puthex64(regs->x1);
    puts("\n");
    puts("x2 : ");
    puthex64(regs->x2);
    puts("\n");
    puts("x3 : ");
    puthex64(regs->x3);
    puts("\n");
    puts("x4 : ");
    puthex64(regs->x4);
    puts("\n");
    puts("x5 : ");
    puthex64(regs->x5);
    puts("\n");
    puts("x6 : ");
    puthex64(regs->x6);
    puts("\n");
    puts("x7 : ");
    puthex64(regs->x7);
    puts("\n");
    puts("x8 : ");
    puthex64(regs->x8);
    puts("\n");
    puts("x16 : ");
    puthex64(regs->x16);
    puts("\n");
    puts("x17 : ");
    puthex64(regs->x17);
    puts("\n");
    puts("x18 : ");
    puthex64(regs->x18);
    puts("\n");
    puts("x29 : ");
    puthex64(regs->x29);
    puts("\n");
    puts("x30 : ");
    puthex64(regs->x30);
    puts("\n");
    puts("x9 : ");
    puthex64(regs->x9);
    puts("\n");
    puts("x10 : ");
    puthex64(regs->x10);
    puts("\n");
    puts("x11 : ");
    puthex64(regs->x11);
    puts("\n");
    puts("x12 : ");
    puthex64(regs->x12);
    puts("\n");
    puts("x13 : ");
    puthex64(regs->x13);
    puts("\n");
    puts("x14 : ");
    puthex64(regs->x14);
    puts("\n");
    puts("x15 : ");
    puthex64(regs->x15);
    puts("\n");
    puts("x19 : ");
    puthex64(regs->x19);
    puts("\n");
    puts("x20 : ");
    puthex64(regs->x20);
    puts("\n");
    puts("x21 : ");
    puthex64(regs->x21);
    puts("\n");
    puts("x22 : ");
    puthex64(regs->x22);
    puts("\n");
    puts("x23 : ");
    puthex64(regs->x23);
    puts("\n");
    puts("x24 : ");
    puthex64(regs->x24);
    puts("\n");
    puts("x25 : ");
    puthex64(regs->x25);
    puts("\n");
    puts("x26 : ");
    puthex64(regs->x26);
    puts("\n");
    puts("x27 : ");
    puthex64(regs->x27);
    puts("\n");
    puts("x28 : ");
    puthex64(regs->x28);
    puts("\n");
    puts("tpidr_el0 : ");
    puthex64(regs->tpidr_el0);
    puts("\n");
    puts("tpidrro_el0 : ");
    puthex64(regs->tpidrro_el0);
    puts("\n");
#endif
}

#ifdef ARCH_riscv64
static void riscv_print_vm_fault()
{
    seL4_Word ip = seL4_GetMR(seL4_VMFault_IP);
    seL4_Word fault_addr = seL4_GetMR(seL4_VMFault_Addr);
    seL4_Word is_instruction = seL4_GetMR(seL4_VMFault_PrefetchFault);
    seL4_Word fsr = seL4_GetMR(seL4_VMFault_FSR);
#if defined(CONFIG_HAVE_CHERI)
    if ((fsr >> 11) & 0x1) {
        puts("MON|ERROR: CHERI Security Violation: ip=");
    } else {
        puts("MON|ERROR: VMFault: ip=");
    }
#else
    puts("MON|ERROR: VMFault: ip=");
#endif
    puthex64(ip);
    puts("  fault_addr=");
    puthex64(fault_addr);
    puts("  fsr=");
    puthex64(fsr);
    puts("  ");
    puts(is_instruction ? "(instruction fault)" : "(data fault)");
    puts("\n");
    puts("MON|ERROR: description of fault: ");
    puts(riscv_fsr_to_string(fsr));
    puts("\n");
#if defined(CONFIG_HAVE_CHERI)
    if ((fsr >> 11) & 1) {
        puts("MON|ERROR: CHERI fault type: ");
        puts(riscv_fsr_cheri_type_to_string((fsr >> 4) & 0xf));
    }
#endif
    puts("\n");
}
#endif

#ifdef ARCH_aarch64
static void aarch64_print_vm_fault()
{
    seL4_Word ip = seL4_GetMR(seL4_VMFault_IP);
    seL4_Word fault_addr = seL4_GetMR(seL4_VMFault_Addr);
    seL4_Word is_instruction = seL4_GetMR(seL4_VMFault_PrefetchFault);
    seL4_Word fsr = seL4_GetMR(seL4_VMFault_FSR);
    seL4_Word ec = fsr >> 26;
    seL4_Word il = fsr >> 25 & 1;
    seL4_Word iss = fsr & 0x1ffffffUL;
    puts("MON|ERROR: VMFault: ip=");
    puthex64(ip);
    puts("  fault_addr=");
    puthex64(fault_addr);
    puts("  fsr=");
    puthex64(fsr);
    puts("  ");
    puts(is_instruction ? "(instruction fault)" : "(data fault)");
    puts("\n");
    puts("MON|ERROR:   ec: ");
    puthex32(ec);
    puts("  ");
    puts(ec_to_string(ec));
    puts("   il: ");
    puts(il ? "1" : "0");
    puts("   iss: ");
    puthex32(iss);
    puts("\n");

    if (ec == 0x24) {
        /* FIXME: Note, this is not a complete decoding of the fault! Just some of the more
           common fields!
        */
        seL4_Word dfsc = iss & 0x3f;
        bool ea = (iss >> 9) & 1;
        bool cm = (iss >> 8) & 1;
        bool s1ptw = (iss >> 7) & 1;
        bool wnr = (iss >> 6) & 1;
        puts("MON|ERROR:   dfsc = ");
        puts(data_abort_dfsc_to_string(dfsc));
        puts(" (");
        puthex32(dfsc);
        puts(")");
        if (ea) {
            puts(" -- external abort");
        }
        if (cm) {
            puts(" -- cache maint");
        }
        if (s1ptw) {
            puts(" -- stage 2 fault for stage 1 page table walk");
        }
        if (wnr) {
            puts(" -- write not read");
        }
        puts("\n");
    }
}
#endif

static void monitor(void)
{
    for (;;) {
        seL4_Word badge, label;
        seL4_MessageInfo_t tag;
        seL4_Error err;

        tag = seL4_Recv(fault_ep, &badge, reply);
        label = seL4_MessageInfo_get_label(tag);

        seL4_Word tcb_cap = pd_tcbs[badge];

        if (label == seL4_Fault_NullFault && badge < MAX_PDS) {
            /* This is a request from our PD to become passive */
            err = seL4_SchedContext_UnbindObject(scheduling_contexts[badge], tcb_cap);
            err = seL4_SchedContext_Bind(scheduling_contexts[badge], notification_caps[badge]);
            if (err != seL4_NoError) {
                puts("MON|ERROR: could not bind scheduling context to notification object");
            } else {
                puts("MON|INFO: PD '");
                puts(pd_names[badge]);
                puts("' is now passive!\n");
            }
            continue;
        }

        puts("MON|ERROR: received message ");
        puthex32(label);
        puts("  badge: ");
        puthex64(badge);
        puts("  tcb cap: ");
        puthex64(tcb_cap);
        puts("\n");

        if (badge < MAX_PDS && pd_names[badge][0] != 0) {
            puts("MON|ERROR: faulting PD: ");
            puts(pd_names[badge]);
            puts("\n");
        } else {
            fail("MON|ERROR: unknown/invalid badge\n");
        }

        seL4_UserContext regs;

        err = seL4_TCB_ReadRegisters(tcb_cap, false, 0, sizeof(seL4_UserContext) / sizeof(seL4_Word), &regs);
        if (err != seL4_NoError) {
            fail("error reading registers");
        }

        print_tcb_registers(&regs, tcb_cap);

        switch (label) {
        case seL4_Fault_CapFault: {
            seL4_Word ip = seL4_GetMR(seL4_CapFault_IP);
            seL4_Word fault_addr = seL4_GetMR(seL4_CapFault_Addr);
            seL4_Word in_recv_phase = seL4_GetMR(seL4_CapFault_InRecvPhase);
            seL4_Word lookup_failure_type = seL4_GetMR(seL4_CapFault_LookupFailureType);
            seL4_Word bits_left = seL4_GetMR(seL4_CapFault_BitsLeft);
            seL4_Word depth_bits_found = seL4_GetMR(seL4_CapFault_DepthMismatch_BitsFound);
            seL4_Word guard_found = seL4_GetMR(seL4_CapFault_GuardMismatch_GuardFound);
            seL4_Word guard_bits_found = seL4_GetMR(seL4_CapFault_GuardMismatch_BitsFound);

            puts("MON|ERROR: CapFault: ip=");
            puthex64(ip);
            puts("  fault_addr=");
            puthex64(fault_addr);
            puts("  in_recv_phase=");
            puts(in_recv_phase == 0 ? "false" : "true");
            puts("  lookup_failure_type=");

            switch (lookup_failure_type) {
            case seL4_NoFailure:
                puts("seL4_NoFailure");
                break;
            case seL4_InvalidRoot:
                puts("seL4_InvalidRoot");
                break;
            case seL4_MissingCapability:
                puts("seL4_MissingCapability");
                break;
            case seL4_DepthMismatch:
                puts("seL4_DepthMismatch");
                break;
            case seL4_GuardMismatch:
                puts("seL4_GuardMismatch");
                break;
            default:
                puthex64(lookup_failure_type);
            }

            if (
                lookup_failure_type == seL4_MissingCapability ||
                lookup_failure_type == seL4_DepthMismatch ||
                lookup_failure_type == seL4_GuardMismatch) {
                puts("  bits_left=");
                puthex64(bits_left);
            }
            if (lookup_failure_type == seL4_DepthMismatch) {
                puts("  depth_bits_found=");
                puthex64(depth_bits_found);
            }
            if (lookup_failure_type == seL4_GuardMismatch) {
                puts("  guard_found=");
                puthex64(guard_found);
                puts("  guard_bits_found=");
                puthex64(guard_bits_found);
            }
            puts("\n");
            break;
        }
        case seL4_Fault_UserException: {
            puts("MON|ERROR: UserException\n");
            break;
        }
        case seL4_Fault_VMFault: {
#if defined(ARCH_aarch64)
            aarch64_print_vm_fault();
#elif defined(ARCH_riscv64)
            riscv_print_vm_fault();
#else
#error "Unknown architecture to print a VM fault for"
#endif

            seL4_Word fault_addr = seL4_GetMR(seL4_VMFault_Addr);
            seL4_Word stack_addr = pd_stack_addrs[badge];
            if (fault_addr < stack_addr && fault_addr >= stack_addr - 0x1000) {
                puts("MON|ERROR: potential stack overflow, fault address within one page outside of stack region\n");
            }

            break;
        }
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
        case seL4_Fault_VCPUFault: {
            seL4_Word esr = seL4_GetMR(seL4_VCPUFault_HSR);
            seL4_Word ec = esr >> 26;

            puts("MON|ERROR: received vCPU fault with ESR: ");
            puthex64(esr);
            puts("\n");

            seL4_Word esr_comment = esr & ESR_COMMENT_MASK;
            if (ec == ARM64_BRK_EC && ((esr_comment & ~UBSAN_ARM64_BRK_MASK) == UBSAN_ARM64_BRK_IMM)) {
                /* We likely have a UBSAN check going off from a brk instruction */
                seL4_Word ubsan_code = esr_comment & UBSAN_ARM64_BRK_MASK;
                puts("MON|ERROR: potential undefined behaviour detected by UBSAN for: '");
                puts(usban_code_to_string(ubsan_code));
                puts("'\n");
            } else {
                puts("MON|ERROR: Unknown vCPU fault\n");
            }
            break;
        }
#endif
        default:
            puts("MON|ERROR: Unknown fault\n");
            puthex64(label);
            break;
        }
    }
}

void main(seL4_BootInfo *bi)
{
    __sel4_ipc_buffer = bi->ipcBuffer;
    puts("MON|INFO: Microkit Bootstrap\n");

    if (!check_untypeds_match(bi)) {
        /* This can be useful to enable during new platform bring up
         * if there are problems
         */
        dump_bootinfo(bi);
        dump_untyped_info();
        fail("MON|ERROR: found mismatch between boot info and untyped info");
    }

    puts("MON|INFO: Number of bootstrap invocations: ");
    puthex32(bootstrap_invocation_count);
    puts("\n");

    puts("MON|INFO: Number of system invocations:    ");
    puthex32(system_invocation_count);
    puts("\n");

    unsigned offset = 0;
    for (unsigned idx = 0; idx < bootstrap_invocation_count; idx++) {
        offset = perform_invocation(bootstrap_invocation_data, offset, idx);
    }
    puts("MON|INFO: completed bootstrap invocations\n");

    offset = 0;
    for (unsigned idx = 0; idx < system_invocation_count; idx++) {
        offset = perform_invocation(system_invocation_data, offset, idx);
    }

#if CONFIG_DEBUG_BUILD
    /*
     * Assign PD/VM names to each TCB with seL4, this helps debugging when an error
     * message is printed by seL4 or if we dump the scheduler state.
     * This is done specifically in the monitor rather than being prepared as an
     * invocation like everything else because it is technically a separate system
     * call and not an invocation.
     * If we end up doing various different kinds of system calls we should add
     * support in the tooling and make the monitor generic.
     */
    for (unsigned idx = 1; idx < pd_names_len + 1; idx++) {
        seL4_DebugNameThread(pd_tcbs[idx], pd_names[idx]);
    }
    for (unsigned idx = 1; idx < vm_names_len + 1; idx++) {
        seL4_DebugNameThread(vm_tcbs[idx], vm_names[idx]);
    }
#endif

    puts("MON|INFO: completed system invocations\n");

    monitor();
}
