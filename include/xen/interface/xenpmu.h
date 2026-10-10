/* SPDX-License-Identifier: MIT */
#ifndef __XEN_PUBLIC_XENPMU_H__
#define __XEN_PUBLIC_XENPMU_H__

#include "xen.h"

#define XENPMU_VER_MAJ    1
#define XENPMU_VER_MIN    0

/*
 * ` enum neg_errnoval
 * ` HYPERVISOR_xenpmu_op(enum xenpmu_op cmd, void *args);
 *
 * The PMU interface is only available to the hardware domain, when Xen has
 * been booted with "vpmu=global" (advertised through XENFEAT_vpmu).  In this
 * mode the hardware domain owns the physical PMU of every pCPU one of its
 * (pinned) vCPUs runs on, and is expected to profile the whole system.
 *
 * All operations act on the pCPU the calling vCPU is pinned to.
 *
 * @cmd  == XENPMU_* (PMU operation)
 * @args == struct xen_pmu_params for XENPMU_{init,finish,lvtpc_set}
 *          struct xen_pmu_reg_batch for XENPMU_{read,write}_regs
 */
/* ` enum xenpmu_op { */
#define XENPMU_init            4 /* Register a xen_pmu_data shared page.     */
#define XENPMU_finish          5 /* Unregister the xen_pmu_data shared page. */
#define XENPMU_lvtpc_set       6 /* Set (only) the mask bit of the LVTPC.     */
#define XENPMU_read_regs       8 /* Read a batch of PMU registers.            */
#define XENPMU_write_regs      9 /* Write a batch of PMU registers.           */
/* ` } */

/*
 * Parameters structure for XENPMU_{init,finish,lvtpc_set}.
 *
 * XENPMU_init:      @vcpu is the vCPU to register the page for, @val the GFN
 *                   of the page to be used as struct xen_pmu_data.
 * XENPMU_finish:    @vcpu is the vCPU to unregister the page for.
 * XENPMU_lvtpc_set: @val is the new LVTPC value.  Only APIC_LVT_MASKED is
 *                   taken into account, the rest is owned by Xen.
 */
struct xen_pmu_params {
	/* IN parameters: interface version (must match XENPMU_VER_MAJ). */
	struct {
		uint32_t maj;
		uint32_t min;
	} version;
	uint64_t val;

	/* IN parameters */
	uint32_t vcpu;
	uint32_t pad;
};

/*
 * PMU register, as accessed by XENPMU_{read,write}_regs.
 *
 * On x86, @index is a MSR index.  Only performance counter related MSRs
 * (counters, event selectors and global controls) are accessible.
 */
struct xen_pmu_reg {
	uint32_t index;
	uint32_t pad;   /* Must be 0. */
	uint64_t value; /* IN for XENPMU_write_regs, OUT for XENPMU_read_regs. */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_pmu_reg);

/*
 * Batch of PMU registers for XENPMU_{read,write}_regs.
 *
 * Registers are processed in order, and processing stops at the first error.
 * On return, @nr holds the number of registers successfully processed.
 */
#define XENPMU_REG_BATCH_MAX 64
struct xen_pmu_reg_batch {
	uint32_t nr;    /* IN/OUT: number of entries in @regs. */
	uint32_t pad;   /* Must be 0. */
	GUEST_HANDLE(xen_pmu_reg) regs;
};

/*
 * Optional shared page between the hypervisor and the hardware domain, one
 * per vCPU (and hence, as vCPUs are pinned, per pCPU).
 *
 * When a page is registered, Xen fills this structure on each PMU interrupt
 * with information about the interrupted context, masks the LVTPC and sends
 * VIRQ_XENPMU to the vCPU.  The guest unmasks the LVTPC (with
 * XENPMU_lvtpc_set, or by writing its virtual LVTPC when it has a local APIC)
 * once it has consumed the sample.
 *
 * Without a registered page, PV vCPUs still get VIRQ_XENPMU (and need to
 * unmask the LVTPC), while vCPUs with a (virtual) local APIC get the
 * interrupt delivered according to their LVTPC.
 *
 * The structure is WO for the hypervisor and RO for the guest.
 */
struct xen_pmu_data {
	/* Interrupted VCPU */
	uint32_t vcpu_id;

	/* Physical processor on which the interrupt occurred. */
	uint32_t pcpu_id;

	/*
	 * Domain that was interrupted: DOMID_SELF, DOMID_XEN or the domain ID of
	 * another domain.
	 */
	domid_t  domain_id;

	uint8_t pad[6];

	/* Architecture-specific information */
	struct xen_pmu_arch pmu;

	/*
	 * Hypervisor call stack, only meaningful when domain_id is DOMID_XEN:
	 * return addresses of the callers of the sampled instruction, innermost
	 * first.  The stack is only provided when Xen is built with frame
	 * pointers, @hv_stack_nr is 0 otherwise.
	 */
	uint32_t hv_stack_nr;
	uint32_t pad2;
#define XENPMU_HV_STACK_MAX 64
	uint64_t hv_stack[XENPMU_HV_STACK_MAX];
};

#endif /* __XEN_PUBLIC_XENPMU_H__ */
