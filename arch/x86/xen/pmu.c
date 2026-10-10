// SPDX-License-Identifier: GPL-2.0
/*
 * PMU support for a PV or PVH hardware domain, when Xen runs with
 * "vpmu=global".
 *
 * In this mode, the hardware domain owns the physical PMU of the pCPUs its
 * (pinned) vCPUs run on, and can profile the whole system:
 *  - PV: PMU MSRs are accessed through XENPMU_{read,write}_regs, and counters
 *    are read with RDPMC, as Xen sets CR4.PCE.
 *  - PVH: PMU MSRs are accessed directly.
 *  - PMIs are delivered through VIRQ_XENPMU, along with information about the
 *    interrupted context in a per-vCPU shared page.  Xen keeps the LVTPC
 *    masked until we acknowledge the PMI with XENPMU_lvtpc_set.
 */
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#include <asm/apicdef.h>
#include <asm/irq_regs.h>
#include <asm/msr.h>
#include <asm/xen/hypercall.h>
#include <xen/events.h>
#include <xen/features.h>
#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/xen.h>
#include <xen/interface/xenpmu.h>

#include "xen-ops.h"

/* x86_pmu.handle_irq definition */
#include "../events/perf_event.h"

struct xenpmu {
	/* Shared page between hypervisor and domain */
	struct xen_pmu_data *xenpmu_data;

	/* A PMI is being handled: LVTPC updates are deferred until its end. */
	bool irq_processing;
	uint32_t lvtpc;

	/* PVH: VIRQ_XENPMU binding (PV binds it in xen_smp_intr_init_pv()). */
	int irq;
	char *irq_name;
};
static DEFINE_PER_CPU(struct xenpmu, xenpmu_shared);
#define get_xenpmu_data()    (this_cpu_ptr(&xenpmu_shared)->xenpmu_data)

/* Counters Xen gives access to. */
#define INTEL_MAX_GP_COUNTERS       8
#define INTEL_MAX_FIXED_COUNTERS    3

bool is_xen_pmu;

static bool is_pmu_msr(u32 msr)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		return (msr >= MSR_K7_EVNTSEL0 && msr <= MSR_K7_PERFCTR3) ||
		       (msr >= MSR_F15H_PERF_CTL0 && msr <= MSR_F15H_PERF_CTR5);

	case X86_VENDOR_INTEL:
	case X86_VENDOR_CENTAUR:
	case X86_VENDOR_ZHAOXIN:
		return (msr >= MSR_IA32_PERFCTR0 &&
			msr < MSR_IA32_PERFCTR0 + INTEL_MAX_GP_COUNTERS) ||
		       (msr >= MSR_IA32_PMC0 &&
			msr < MSR_IA32_PMC0 + INTEL_MAX_GP_COUNTERS) ||
		       (msr >= MSR_P6_EVNTSEL0 &&
			msr < MSR_P6_EVNTSEL0 + INTEL_MAX_GP_COUNTERS) ||
		       (msr >= MSR_CORE_PERF_FIXED_CTR0 &&
			msr < MSR_CORE_PERF_FIXED_CTR0 +
			      INTEL_MAX_FIXED_COUNTERS) ||
		       (msr >= MSR_CORE_PERF_FIXED_CTR_CTRL &&
			msr <= MSR_CORE_PERF_GLOBAL_OVF_CTRL);

	default:
		return false;
	}
}

static int xen_pmu_reg_op(unsigned int op, u32 msr, u64 *val)
{
	struct xen_pmu_reg reg = { .index = msr, .value = *val };
	struct xen_pmu_reg_batch batch = { .nr = 1 };
	int ret;

	set_xen_guest_handle(batch.regs, &reg);

	ret = HYPERVISOR_xenpmu_op(op, &batch);
	if (!ret && op == XENPMU_read_regs)
		*val = reg.value;

	return ret;
}

/*
 * Access PMU MSRs through the hypervisor.  Returns true if @msr was handled,
 * in which case @err (if not NULL) is set as {read,write}_msr_safe() would.
 */
bool pmu_msr_chk_emulated(u32 msr, u64 *val, bool is_read, int *err)
{
	int ret;

	if (!is_xen_pmu || !is_pmu_msr(msr))
		return false;

	ret = xen_pmu_reg_op(is_read ? XENPMU_read_regs : XENPMU_write_regs,
			     msr, val);
	if (ret) {
		if (is_read)
			*val = 0;

		if (err)
			*err = -EIO;
		else
			pr_warn_once("Failed to %s PMU MSR %#x: %d\n",
				     is_read ? "read" : "write", msr, ret);
	}

	return true;
}

u64 xen_read_pmc(int counter)
{
	/* Xen sets CR4.PCE when we own the PMU. */
	if (is_xen_pmu)
		return native_read_pmc(counter);

	return 0;
}

static int xen_pmu_lvtpc_set(uint32_t val)
{
	struct xen_pmu_params xp = {
		.version.maj = XENPMU_VER_MAJ,
		.version.min = XENPMU_VER_MIN,
		.val = val,
	};

	return HYPERVISOR_xenpmu_op(XENPMU_lvtpc_set, &xp);
}

int pmu_apic_update(uint32_t val)
{
	struct xenpmu *pmu = this_cpu_ptr(&xenpmu_shared);

	if (!pmu->xenpmu_data) {
		pr_warn_once("%s: pmudata not initialized\n", __func__);
		return -EINVAL;
	}

	if (pmu->irq_processing) {
		pmu->lvtpc = val;
		return 0;
	}

	return xen_pmu_lvtpc_set(val);
}

/*
 * perf callbacks
 *
 * The shared page describes the context interrupted by the PMI being handled,
 * it is stale outside of xen_pmu_irq_handler().
 */
static unsigned int xen_guest_state(void)
{
	const struct xenpmu *pmu = this_cpu_ptr(&xenpmu_shared);
	const struct xen_pmu_data *xenpmu_data = pmu->xenpmu_data;
	unsigned int state = 0;

	if (!xenpmu_data || !pmu->irq_processing)
		return state;

	if (xenpmu_data->domain_id == DOMID_XEN)
		return PERF_GUEST_HYPERVISOR;

	/* Samples from ourselves aren't guest samples. */
	if (xenpmu_data->domain_id >= DOMID_SELF)
		return state;

	state |= PERF_GUEST_ACTIVE;

	if (xenpmu_data->pmu.pmu_flags & PMU_SAMPLE_PV) {
		if (xenpmu_data->pmu.pmu_flags & PMU_SAMPLE_USER)
			state |= PERF_GUEST_USER;
	} else if (xenpmu_data->pmu.r.regs.cpl & 3) {
		state |= PERF_GUEST_USER;
	}

	return state;
}

static unsigned long xen_get_guest_ip(void)
{
	const struct xen_pmu_data *xenpmu_data = get_xenpmu_data();

	if (!xenpmu_data) {
		pr_warn_once("%s: pmudata not initialized\n", __func__);
		return 0;
	}

	return xenpmu_data->pmu.r.regs.ip;
}

/* Context of this vCPU when entering Xen, for hypervisor callchains. */
static DEFINE_PER_CPU(struct pt_regs, xen_hv_caller_regs);

static struct pt_regs *
xen_hypervisor_callchain(struct perf_callchain_entry_ctx *entry,
			 struct pt_regs *regs)
{
	const struct xen_pmu_data *xenpmu_data = get_xenpmu_data();
	const struct xen_pmu_regs *g = &xenpmu_data->pmu.g.regs;
	struct pt_regs *caller, *irq_regs;
	unsigned int i, nr;

	if (perf_callchain_store(entry, xenpmu_data->pmu.r.regs.ip))
		return NULL;

	nr = min(READ_ONCE(xenpmu_data->hv_stack_nr), XENPMU_HV_STACK_MAX);
	for (i = 0; i < nr; i++)
		if (perf_callchain_store(entry, xenpmu_data->hv_stack[i]))
			return NULL;

	if (!(xenpmu_data->pmu.pmu_flags & PMU_SAMPLE_CALLER))
		return NULL;

	/*
	 * Xen was running on our behalf, e.g. in a hypercall, and the PMI is
	 * handled the first time events are unmasked since then.  This happens
	 * before we schedule, hence the caller context is still the one of the
	 * current task:
	 *  - from user mode, its user stack is intact.
	 *  - from kernel mode, its stack is intact if we are handling the PMI
	 *    upon returning from Xen.  Otherwise, events were masked (e.g.
	 *    multicalls are issued with interrupts disabled, the return to user
	 *    mode unmasks them in HYPERVISOR_iret) and we moved on until
	 *    unmasking them: the best we can do is to carry on from there,
	 *    which shares the callers of the hypercall site.
	 */
	irq_regs = get_irq_regs();
	if (!irq_regs)
		return NULL;

	if (!g->cpl && irq_regs->sp != g->sp)
		return irq_regs;

	caller = this_cpu_ptr(&xen_hv_caller_regs);
	memset(caller, 0, sizeof(*caller));
	caller->ip = g->ip;
	caller->sp = g->sp;
	caller->bp = g->bp;
	caller->flags = g->flags;
	caller->cs = (g->cs & ~3) | (g->cpl & 3);
	caller->ss = g->ss;

	return caller;
}

static struct perf_guest_info_callbacks xen_guest_cbs = {
	.state                  = xen_guest_state,
	.get_ip			= xen_get_guest_ip,
	.hypervisor_callchain	= xen_hypervisor_callchain,
};

/* Convert registers from Xen's format to Linux' */
static void xen_convert_regs(const struct xen_pmu_regs *xen_regs,
			     struct pt_regs *regs, uint64_t pmu_flags)
{
	regs->ip = xen_regs->ip;
	regs->cs = xen_regs->cs;
	regs->sp = xen_regs->sp;
	regs->flags = xen_regs->flags;

	if (pmu_flags & PMU_SAMPLE_PV) {
		if (pmu_flags & PMU_SAMPLE_USER)
			regs->cs |= 3;
		else
			regs->cs &= ~3;
	} else {
		if (xen_regs->cpl)
			regs->cs |= 3;
		else
			regs->cs &= ~3;
	}
}

irqreturn_t xen_pmu_irq_handler(int irq, void *dev_id)
{
	struct xenpmu *pmu = this_cpu_ptr(&xenpmu_shared);
	const struct xen_pmu_data *xenpmu_data = pmu->xenpmu_data;
	irqreturn_t ret = IRQ_NONE;
	struct pt_regs regs = {0};
	int err;

	if (!xenpmu_data) {
		pr_warn_once("%s: pmudata not initialized\n", __func__);
		return ret;
	}

	/* Unless the handler asks otherwise, re-arm the PMI once done. */
	pmu->lvtpc = APIC_DM_NMI;
	pmu->irq_processing = true;

	xen_convert_regs(&xenpmu_data->pmu.r.regs, &regs,
			 xenpmu_data->pmu.pmu_flags);
	if (x86_pmu.handle_irq(&regs))
		ret = IRQ_HANDLED;

	pmu->irq_processing = false;

	err = xen_pmu_lvtpc_set(pmu->lvtpc);
	if (err) {
		pr_warn_once("%s: failed hypercall, err: %d\n", __func__, err);
		return IRQ_NONE;
	}

	return ret;
}

/*
 * PVH: PMIs are delivered through VIRQ_XENPMU once the shared page is set.
 * The binding is kept until we are done for good, as xen_pmu_finish() may be
 * called from contexts which can't sleep.
 */
static int xen_pmu_bind_virq(int cpu)
{
	struct xenpmu *pmu = per_cpu_ptr(&xenpmu_shared, cpu);
	int irq;

	if (xen_pv_domain() || pmu->irq_name)
		return 0;

	pmu->irq_name = kasprintf(GFP_KERNEL, "pmu%d", cpu);
	if (!pmu->irq_name)
		return -ENOMEM;

	irq = bind_virq_to_irqhandler(VIRQ_XENPMU, cpu, xen_pmu_irq_handler,
				      IRQF_PERCPU | IRQF_NOBALANCING,
				      pmu->irq_name, NULL);
	if (irq < 0) {
		kfree(pmu->irq_name);
		pmu->irq_name = NULL;
		return irq;
	}

	pmu->irq = irq;

	return 0;
}

static void xen_pmu_unbind_virq(int cpu)
{
	struct xenpmu *pmu = per_cpu_ptr(&xenpmu_shared, cpu);

	if (!pmu->irq_name)
		return;

	unbind_from_irqhandler(pmu->irq, NULL);
	kfree(pmu->irq_name);
	pmu->irq_name = NULL;
}

void xen_pmu_init(int cpu)
{
	int err;
	struct xen_pmu_params xp;
	unsigned long pfn;
	struct xen_pmu_data *xenpmu_data;

	BUILD_BUG_ON(sizeof(struct xen_pmu_data) > PAGE_SIZE);

	if (!(xen_pv_domain() || xen_pvh_domain()) || !xen_initial_domain() ||
	    !xen_feature(XENFEAT_vpmu) || (cpu != 0 && !is_xen_pmu))
		return;

	xenpmu_data = (struct xen_pmu_data *)get_zeroed_page(GFP_KERNEL);
	if (!xenpmu_data) {
		pr_err("VPMU init: No memory\n");
		return;
	}
	pfn = virt_to_pfn(xenpmu_data);

	/* Ready to handle PMIs as soon as Xen knows about the page. */
	per_cpu(xenpmu_shared, cpu).xenpmu_data = xenpmu_data;
	per_cpu(xenpmu_shared, cpu).irq_processing = false;

	err = xen_pmu_bind_virq(cpu);
	if (err)
		goto fail;

	xp.val = pfn_to_mfn(pfn);
	xp.vcpu = cpu;
	xp.version.maj = XENPMU_VER_MAJ;
	xp.version.min = XENPMU_VER_MIN;
	err = HYPERVISOR_xenpmu_op(XENPMU_init, &xp);
	if (err) {
		xen_pmu_unbind_virq(cpu);
		goto fail;
	}

	if (!is_xen_pmu) {
		is_xen_pmu = true;
		perf_register_guest_info_callbacks(&xen_guest_cbs);
	}

	return;

fail:
	per_cpu(xenpmu_shared, cpu).xenpmu_data = NULL;
	if (err == -EOPNOTSUPP || err == -ENOSYS)
		pr_info_once("VPMU disabled by hypervisor.\n");
	else
		pr_info_once("Could not initialize VPMU for cpu %d, error %d\n",
			cpu, err);
	free_pages((unsigned long)xenpmu_data, 0);
}

void xen_pmu_finish(int cpu)
{
	struct xen_pmu_params xp;

	if (!per_cpu(xenpmu_shared, cpu).xenpmu_data)
		return;

	xp.vcpu = cpu;
	xp.version.maj = XENPMU_VER_MAJ;
	xp.version.min = XENPMU_VER_MIN;

	(void)HYPERVISOR_xenpmu_op(XENPMU_finish, &xp);

	free_pages((unsigned long)per_cpu(xenpmu_shared, cpu).xenpmu_data, 0);
	per_cpu(xenpmu_shared, cpu).xenpmu_data = NULL;
}
