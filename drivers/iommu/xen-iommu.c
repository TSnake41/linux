// SPDX-License-Identifier: GPL-2.0

/*
 * Xen PV-IOMMU driver.
 *
 * Copyright (C) 2024 Vates SAS
 * 
 * Author: Teddy Astie <teddy.astie@vates.tech>
 *
 */

#define pr_fmt(fmt)	"xen-iommu: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/iommu.h>
#include <linux/dma-map-ops.h>
#include <linux/pci.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/device/driver.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>
#include <asm/iommu.h>
#include <asm/string.h>

#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/physdev.h>
#include <xen/interface/pv-iommu.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

MODULE_DESCRIPTION("Xen IOMMU driver");
MODULE_AUTHOR("Teddy Astie <teddy.astie@vates.tech>");
MODULE_LICENSE("GPL");

#define MSI_RANGE_START		(0xfee00000)
#define MSI_RANGE_END		(0xfeefffff)

#define XEN_IOMMU_PGSIZES       (0x1000)

/* TODO: Remove hardcoded 39-bits limit */
#define XEN_IOMMU_ADDR_MAX ((1ULL << 39) - 1)

/* Maximum amount of batched hypercalls before flushing. */
#define XEN_IOMMU_MAX_HYPERCALL     (64)

struct xen_iommu_domain {
    struct iommu_domain domain;
    
    u16 ctx_no; /* Xen PV-IOMMU context number */
};

static struct iommu_device xen_iommu_device;

/* Queue for batching map operations */
static spinlock_t hypercall_queue_lock;
static size_t hypercall_queue_count;
static struct pv_iommu_op hypercall_queue[XEN_IOMMU_MAX_HYPERCALL];

static void flush_queue(void)
{
    size_t i;
    
    pr_debug("Flushing hypercall queue");

    HYPERVISOR_iommu_op(hypercall_queue, hypercall_queue_count);

    for (i = 0; i < hypercall_queue_count; i++) {
        pr_debug("Issued hypercall %d ctx_no=%d, flags=%4x", hypercall_queue[i].subop_id,
            hypercall_queue[i].ctx_no, hypercall_queue[i].flags);

        /* TODO: Check errors ? */
    }

    hypercall_queue_count = 0;
}

static void push_hypercall(struct pv_iommu_op op)
{
    spin_lock(&hypercall_queue_lock);
    
    hypercall_queue[hypercall_queue_count] = op;
    hypercall_queue_count++;

    if (hypercall_queue_count == XEN_IOMMU_MAX_HYPERCALL)
        flush_queue();

    spin_unlock(&hypercall_queue_lock);
}

static inline struct xen_iommu_domain *to_xen_iommu_domain(struct iommu_domain *dom)
{
    return container_of(dom, struct xen_iommu_domain, domain);
}

static inline u64 addr_to_pfn(u64 addr)
{
    return addr >> 12;
}

static inline u64 pfn_to_addr(u64 pfn)
{
    return pfn << 12;
}

bool xen_iommu_capable(struct device *dev, enum iommu_cap cap)
{
    /* No specific iommu_cap */
    return false;
}

struct iommu_domain *xen_iommu_domain_alloc(unsigned type)
{
    struct xen_iommu_domain *domain;
    u16 ctx_no;
    int ret;

    if (type & IOMMU_DOMAIN_IDENTITY) {
        /* use default domain */
        ctx_no = 0;
    } else {
        struct pv_iommu_op op = {
            .ctx_no = 0,
            .flags = 0,
            .subop_id = IOMMUOP_alloc_context
        };
        
        ret = HYPERVISOR_iommu_op(&op, 1);

        if (ret) {
            pr_err("Unable to create Xen IOMMU context (%d)", ret);
            return ERR_PTR(ret);
        }

        ctx_no = op.ctx_no;
    }

    domain = kzalloc(sizeof(*domain), GFP_KERNEL);

    domain->ctx_no = ctx_no;

    domain->domain.geometry.aperture_start = 0;

    domain->domain.geometry.aperture_end = XEN_IOMMU_ADDR_MAX;
    domain->domain.geometry.force_aperture = true;

    return &domain->domain;
}

struct iommu_group *xen_iommu_device_group(struct device *dev)
{
	if (!dev_is_pci(dev))
		return ERR_PTR(-ENODEV);

	return pci_device_group(dev);
}

struct iommu_device *xen_iommu_probe_device(struct device *dev)
{
    if (!dev_is_pci(dev))
        return ERR_PTR(-ENODEV);

    return &xen_iommu_device;
}

static void xen_iommu_probe_finalize(struct device *dev)
{
	set_dma_ops(dev, NULL);
	iommu_setup_dma_ops(dev, 0, XEN_IOMMU_ADDR_MAX);
}

void xen_iommu_release_device(struct device *dev)
{
    int ret;
    struct pci_dev *pdev;
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_reattach_device,
        .flags = 0,
        .ctx_no = 0 /* reattach device back to default context */
    };

    if (!dev_is_pci(dev))
        return;

    pdev = to_pci_dev(dev);

    op.reattach_device.dev.seg = pci_domain_nr(pdev->bus);
    op.reattach_device.dev.bus = pdev->bus->number;
    op.reattach_device.dev.devfn = pdev->devfn;

    ret = HYPERVISOR_iommu_op(&op, 1);

    if (ret)
        pr_warn("Unable to release device %p\n", &op.reattach_device.dev);
}

int xen_iommu_map_pages(struct iommu_domain *domain, unsigned long iova,
                        phys_addr_t paddr, size_t pgsize, size_t pgcount,
			            int prot, gfp_t gfp, size_t *mapped)
{
    /* TODO: better handling, batching, ... */
    size_t count = (pgsize / XEN_PAGE_SIZE) * pgcount;
    size_t i;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_map_page,
        .flags = 0,
        .ctx_no = dom->ctx_no
    };

    if (WARN(!dom->ctx_no, "Tried to map page to default context"))
        return -EINVAL;

    pr_debug("Mapping to %lx %zu %zu paddr %x", iova, pgsize, pgcount, paddr);

    if (prot & IOMMU_READ)
        op.flags |= IOMMU_OP_readable;

    if (prot & IOMMU_WRITE)
        op.flags |= IOMMU_OP_writeable;

    for (i = 0; i < count; ++i) {
        pr_debug("Mapping %lx+%x at %lx+%x\n", pfn_to_gfn(addr_to_pfn(paddr)), i, addr_to_pfn(iova), i);
        op.map_page.gfn = pfn_to_gfn(addr_to_pfn(paddr)) + i;
        op.map_page.dfn = addr_to_pfn(iova) + i;

        push_hypercall(op);
        
        if (mapped)
            *mapped += XEN_PAGE_SIZE;
    }

    if (mapped)
        pr_debug("Mapped %zx", *mapped);

    return 0;
}

size_t xen_iommu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
			                 size_t pgsize, size_t pgcount,
			                 struct iommu_iotlb_gather *iotlb_gather)
{
    int ret;
    size_t i, count = (pgsize / XEN_PAGE_SIZE) * pgcount;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_unmap_page,
        .ctx_no = dom->ctx_no,
        .flags = 0,
    };
    
    if (WARN(!dom->ctx_no, "Tried to unmap page to default context"))
        return -EINVAL;

    for (i = 0; i < count; ++i) {
        pr_debug("Unmapping %lx+%x\n", addr_to_pfn(iova), i);
        op.unmap_page.dfn = addr_to_pfn(iova) + i;

        push_hypercall(op);
    }

    return pgcount * pgsize;
}

int xen_iommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
    struct pci_dev *pdev;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_reattach_device,
        .flags = 0,
        .ctx_no = dom->ctx_no,
    };

    if (!dev_is_pci(dev))
        return -EINVAL;

    pdev = to_pci_dev(dev);

    op.reattach_device.dev.seg = pci_domain_nr(pdev->bus);
    op.reattach_device.dev.bus = pdev->bus->number;
    op.reattach_device.dev.devfn = pdev->devfn;

    /* Ensure the mappings are coherent when moving the device */
    spin_lock(&hypercall_queue_lock);
    flush_queue();
    spin_unlock(&hypercall_queue_lock);

    return HYPERVISOR_iommu_op(&op, 1);
}

void xen_iommu_free(struct iommu_domain *domain)
{
    int ret;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);

    if (dom->ctx_no != 0) {
        struct pv_iommu_op op = {
            .ctx_no = dom->ctx_no,
            .flags = 0,
            .subop_id = IOMMUOP_free_context
        };

        /* Make sure that no pending operation target this domain */
        spin_lock(&hypercall_queue_lock);
        flush_queue();

        ret = HYPERVISOR_iommu_op(&op, 1);
        spin_unlock(&hypercall_queue_lock);

        if (ret)
            pr_err("Context %hu destruction failure", dom->ctx_no);
    }

    kfree(domain);
}

phys_addr_t xen_iommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
    int ret;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);

    struct pv_iommu_op op = {
        .ctx_no = dom->ctx_no,
        .flags = 0,
        .subop_id = IOMMUOP_lookup_page,
    };

    op.lookup_page.dfn = addr_to_pfn(iova);
    
    spin_lock(&hypercall_queue_lock);
    flush_queue();

    ret = HYPERVISOR_iommu_op(&op, 1);
    spin_unlock(&hypercall_queue_lock);

    if (ret)
        return 0;

    phys_addr_t page_addr = pfn_to_addr(gfn_to_pfn(op.lookup_page.gfn));

    /* Consider non-aligned iova */
    return page_addr + (iova & 0xFFF);
}

void xen_iommu_get_resv_regions(struct device *device, struct list_head *head)
{
    struct iommu_resv_region *reg;
    
    reg = iommu_alloc_resv_region(MSI_RANGE_START,
        MSI_RANGE_END - MSI_RANGE_START + 1,
        0, IOMMU_RESV_MSI, GFP_KERNEL);
    
    if (!reg)
		return;

	list_add_tail(&reg->list, head);
}

static struct iommu_ops xen_iommu_ops = {
    .capable = xen_iommu_capable,
    .domain_alloc = xen_iommu_domain_alloc,
    .probe_device = xen_iommu_probe_device,
    .probe_finalize = xen_iommu_probe_finalize,
    .device_group = xen_iommu_device_group,
    .release_device = xen_iommu_release_device,
    .get_resv_regions = xen_iommu_get_resv_regions,
    .pgsize_bitmap = XEN_IOMMU_PGSIZES,
    .default_domain_ops = &(const struct iommu_domain_ops) {
        .map_pages = xen_iommu_map_pages,
        .unmap_pages = xen_iommu_unmap_pages,
        .attach_dev = xen_iommu_attach_dev,
        .iova_to_phys = xen_iommu_iova_to_phys,
        .free = xen_iommu_free,
    },
};

int __init xen_iommu_init(void)
{
    int ret;
    struct pv_iommu_op op = { .subop_id = 0 };

	if (!xen_domain())
		return -ENODEV;

    if (!xen_initial_domain())
        return -EPERM;

    /* Check if iommu_op is supported */
    if (HYPERVISOR_iommu_op(&op, 1) == -ENOSYS)
        return -ENODEV; /* No Xen IOMMU hardware */

	pr_info("Initialising Xen IOMMU driver\n");

    ret = iommu_device_sysfs_add(&xen_iommu_device, NULL, NULL, "xen-iommu");
    if (ret) {
        pr_err("Unable to add Xen IOMMU sysfs");
        return ret;
    }

    ret = iommu_device_register(&xen_iommu_device, &xen_iommu_ops, NULL);
    if (ret) {
        pr_err("Unable to register Xen IOMMU device %d\n", ret);
        iommu_device_sysfs_remove(&xen_iommu_device);
        return ret;
    }

    /* swiotlb is redundant when IOMMU is active. */
    x86_swiotlb_enable = false;

    return 0;
}

void __exit xen_iommu_fini(void)
{
	pr_info("Unregistering Xen IOMMU driver\n");
    
    iommu_device_unregister(&xen_iommu_device);
    iommu_device_sysfs_remove(&xen_iommu_device);
}

module_init(xen_iommu_init);
module_exit(xen_iommu_fini);
