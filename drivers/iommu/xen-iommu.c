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
#include <linux/minmax.h>
#include <asm/iommu.h>
#include <asm/string.h>

#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/memory.h>
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

struct xen_iommu_domain {
    struct iommu_domain domain;

    u16 ctx_no; /* Xen PV-IOMMU context number */
};

static struct iommu_device xen_iommu_device;

static uint32_t max_nr_pages;
static uint64_t max_iova_addr;

static spinlock_t lock;

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
    switch (cap) {
        case IOMMU_CAP_CACHE_COHERENCY:
            return true;
        
        default:
            return false;
    }
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
        
        ret = HYPERVISOR_iommu_op(&op);

        if (ret) {
            pr_err("Unable to create Xen IOMMU context (%d)", ret);
            return ERR_PTR(ret);
        }

        ctx_no = op.ctx_no;
    }

    domain = kzalloc(sizeof(*domain), GFP_KERNEL);

    domain->ctx_no = ctx_no;

    domain->domain.geometry.aperture_start = 0;

    domain->domain.geometry.aperture_end = max_iova_addr;
    domain->domain.geometry.force_aperture = true;

    return &domain->domain;
}

static struct iommu_group *xen_iommu_device_group(struct device *dev)
{
    if (!dev_is_pci(dev))
        return ERR_PTR(-ENODEV);

    return pci_device_group(dev);
}

static struct iommu_device *xen_iommu_probe_device(struct device *dev)
{
    if (!dev_is_pci(dev))
        return ERR_PTR(-ENODEV);

    return &xen_iommu_device;
}

static void xen_iommu_probe_finalize(struct device *dev)
{
    set_dma_ops(dev, NULL);
    iommu_setup_dma_ops(dev, 0, max_iova_addr);
}

static void xen_iommu_release_device(struct device *dev)
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

    ret = HYPERVISOR_iommu_op(&op);

    if (ret)
        pr_warn("Unable to release device %p\n", &op.reattach_device.dev);
}

static int xen_iommu_map_pages(struct iommu_domain *domain, unsigned long iova,
                               phys_addr_t paddr, size_t pgsize, size_t pgcount,
                               int prot, gfp_t gfp, size_t *mapped)
{
    size_t xen_pg_count = (pgsize / XEN_PAGE_SIZE) * pgcount;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_map_pages,
        .flags = 0,
        .ctx_no = dom->ctx_no
    };
    /* NOTE: paddr is actually bound to pfn, not gfn */
    uint64_t pfn = addr_to_pfn(paddr);
    uint64_t dfn = addr_to_pfn(iova);
    int ret = 0;

    if (WARN(!dom->ctx_no, "Tried to map page to default context"))
        return -EINVAL;

    //pr_info("Mapping to %lx %zu %zu paddr %x\n", iova, pgsize, pgcount, paddr);

    if (prot & IOMMU_READ)
        op.flags |= IOMMU_OP_readable;

    if (prot & IOMMU_WRITE)
        op.flags |= IOMMU_OP_writeable;

    while (xen_pg_count) {
        size_t to_map = min(xen_pg_count, max_nr_pages);
        uint64_t gfn = pfn_to_gfn(pfn);

        //pr_info("Mapping %lx-%lx at %lx-%lx\n", gfn, gfn + to_map - 1, dfn, dfn + to_map - 1);

        op.map_pages.gfn = gfn;
        op.map_pages.dfn = dfn;

        op.map_pages.nr_pages = to_map;

        ret = HYPERVISOR_iommu_op(&op);
        
        //pr_info("map_pages.mapped = %u\n", op.map_pages.mapped);
        
        if (mapped)
            *mapped += XEN_PAGE_SIZE * op.map_pages.mapped;
        
        if (ret)
            break;

        xen_pg_count -= to_map;

        pfn += to_map;
        dfn += to_map;
    }

    return ret;
}

static size_t xen_iommu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
                                    size_t pgsize, size_t pgcount,
                                    struct iommu_iotlb_gather *iotlb_gather)
{
    size_t xen_pg_count = (pgsize / XEN_PAGE_SIZE) * pgcount;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_unmap_pages,
        .ctx_no = dom->ctx_no,
        .flags = 0,
    };
    uint64_t dfn = addr_to_pfn(iova);
    int ret = 0;

    if (WARN(!dom->ctx_no, "Tried to unmap page to default context"))
        return -EINVAL;

    while (xen_pg_count) {
        size_t to_unmap = min(xen_pg_count, max_nr_pages);

        //pr_info("Unmapping %lx-%lx\n", dfn, dfn + to_unmap - 1);

        op.unmap_pages.dfn = dfn;
        op.unmap_pages.nr_pages = to_unmap;

        ret = HYPERVISOR_iommu_op(&op);

        if (ret)
            pr_warn("Unmap failure (%lx-%lx)\n", dfn, dfn + to_unmap - 1);

        xen_pg_count -= to_unmap;

        dfn += to_unmap;
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
    
    return HYPERVISOR_iommu_op(&op);
}

static void xen_iommu_free(struct iommu_domain *domain)
{
    int ret;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);

    if (dom->ctx_no != 0) {
        struct pv_iommu_op op = {
            .ctx_no = dom->ctx_no,
            .flags = 0,
            .subop_id = IOMMUOP_free_context
        };

        ret = HYPERVISOR_iommu_op(&op);

        if (ret)
            pr_err("Context %hu destruction failure\n", dom->ctx_no);
    }

    kfree(domain);
}

static phys_addr_t xen_iommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
    int ret;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);

    struct pv_iommu_op op = {
        .ctx_no = dom->ctx_no,
        .flags = 0,
        .subop_id = IOMMUOP_lookup_page,
    };

    op.lookup_page.dfn = addr_to_pfn(iova);
    
    ret = HYPERVISOR_iommu_op(&op);

    if (ret)
        return 0;

    phys_addr_t page_addr = pfn_to_addr(gfn_to_pfn(op.lookup_page.gfn));

    /* Consider non-aligned iova */
    return page_addr + (iova & 0xFFF);
}

static void xen_iommu_get_resv_regions(struct device *dev, struct list_head *head)
{
    struct iommu_resv_region *reg;
    struct xen_reserved_device_memory *entries;
    struct xen_reserved_device_memory_map map;
    struct pci_dev *pdev;
    int ret, i;

    if (!dev_is_pci(dev))
        return;

    pdev = to_pci_dev(dev);

    reg = iommu_alloc_resv_region(MSI_RANGE_START,
        MSI_RANGE_END - MSI_RANGE_START + 1,
        0, IOMMU_RESV_MSI, GFP_KERNEL);
    
    if (!reg)
        return;

    list_add_tail(&reg->list, head);

    /* Map xen-specific entries */

    /* First, get number of entries to map */
    map.buffer = NULL;
    map.nr_entries = 0;
    map.flags = 0;
    
    map.dev.pci.seg = pci_domain_nr(pdev->bus);
    map.dev.pci.bus = pdev->bus->number;
    map.dev.pci.devfn = pdev->devfn;

    ret = HYPERVISOR_memory_op(XENMEM_reserved_device_memory_map, &map);

    if (ret == 0)
        /* No reserved region, nothing to do */
        return;

    if (ret != -ENOBUFS)
    {
        pr_err("Unable to get reserved region count (%d)\n", ret);
        return;
    }

    /* Assume a reasonable number of entries, otherwise, something is probably wrong */
    if (WARN_ON(map.nr_entries > 256))
        pr_warn("Xen reporting many reserved regions (%u)\n", map.nr_entries);

    /* And finally get actual mappings */
    entries = kcalloc(map.nr_entries, sizeof(struct xen_reserved_device_memory),
                      GFP_KERNEL);
    
    if (!entries)
    {
        pr_err("No memory for map entries\n");
        return;
    }
    
    map.buffer = entries;

    ret = HYPERVISOR_memory_op(XENMEM_reserved_device_memory_map, &map);

    if (ret != 0)
    {
        pr_err("Unable to get reserved regions (%d)\n", ret);
        kfree(entries);
        return;
    }

    for (i = 0; i < map.nr_entries; i++)
    {
        struct xen_reserved_device_memory entry = entries[i];

        reg = iommu_alloc_resv_region(pfn_to_addr(entry.start_pfn),
                                      pfn_to_addr(entry.nr_pages),
                                      0, IOMMU_RESV_RESERVED, GFP_KERNEL);

        if (!reg)
            break;

        list_add_tail(&reg->list, head);
    }

    kfree(entries);
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
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_query_capabilities
    };

    if (!xen_domain())
        return -ENODEV;

    /* Check if iommu_op is supported */
    if (HYPERVISOR_iommu_op(&op) == -ENOSYS)
        return -ENODEV; /* No Xen IOMMU hardware */

    pr_info("Initialising Xen IOMMU driver\n");
    pr_info("max_nr_pages=%d\n", op.cap.max_nr_pages);
    pr_info("max_ctx_no=%d\n", op.cap.max_ctx_no);
    pr_info("max_iova_addr=%llx\n", op.cap.max_iova_addr);

    if (op.cap.max_ctx_no == 0) {
        pr_err("Unable to use IOMMU PV driver (no context available)\n");
        return -ENOTSUPP; /* Unable to use IOMMU PV ? */
    }

    if (xen_domain_type == XEN_PV_DOMAIN)
        /* TODO: In PV domain, due to the existing pfn-gfn mapping we need to
         * consider that under certains circonstances, we have :
         *   pfn_to_gfn(x + 1) != pfn_to_gfn(x) + 1
         * 
         * In these cases, we would want to separate the subop into several calls.
         * (only doing the grouped operation when the mapping is actually contigous)
         * Only map operation would be affected, as unmap actually uses dfn which
         * doesn't have this kind of mapping.
         *
         * Force single-page operations to work arround this issue for now.
         */
        max_nr_pages = 1;
    else
        /* With HVM domains, pfn_to_gfn is identity, there is no issue regarding this. */
        max_nr_pages = op.cap.max_nr_pages;

    max_iova_addr = op.cap.max_iova_addr;

    spin_lock_init(&lock);

    ret = iommu_device_sysfs_add(&xen_iommu_device, NULL, NULL, "xen-iommu");
    if (ret) {
        pr_err("Unable to add Xen IOMMU sysfs\n");
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
