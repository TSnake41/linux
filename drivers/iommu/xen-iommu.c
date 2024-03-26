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

#include <linux/err.h>
#include <linux/module.h>
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/minmax.h>
#include <linux/io-pgtable.h>

#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/memory.h>
#include <xen/interface/pv-iommu.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

MODULE_DESCRIPTION("Xen IOMMU driver");
MODULE_AUTHOR("Teddy Astie <teddy.astie@vates.tech>");
MODULE_LICENSE("GPL");

#define MSI_RANGE_START		(0xfee00000)
#define MSI_RANGE_END		(0xfeefffff)

struct xen_iommu_domain {
	struct iommu_domain domain;

	u16 ctx_no;			/* Xen PV-IOMMU context number */
	struct io_pgtable_ops *pgtable;	/* Parralel page table for iova_to_phys */
};

static struct iommu_device xen_iommu_device;
static struct pv_iommu_capabilities caps;

static struct xen_iommu_domain xen_iommu_identity_domain;
static bool map_single_pages = false;

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

static bool xen_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;

	default:
		return false;
	}
}

static struct iommu_domain *xen_iommu_domain_alloc_paging(struct device *dev)
{
	struct xen_iommu_domain *domain;
	struct io_pgtable_cfg cfg = { .alloc = NULL, .free = NULL };
	struct io_pgtable_ops *pgtable;
	int ret;

	struct pv_iommu_alloc alloc = { .alloc_flags = 0 };

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	pgtable = alloc_io_pgtable_ops(XEN_IOMMU_GENERIC, &cfg, NULL);
	if (!pgtable) {
		kfree(domain);
		return ERR_PTR(-ENOMEM);
	}

	ret = HYPERVISOR_iommu_op(IOMMU_alloc_context, &alloc);

	if (ret) {
		pr_err("Unable to create Xen IOMMU context (%d)", ret);
		kfree(domain);
		free_io_pgtable_ops(pgtable);
		return ERR_PTR(ret);
	}

	domain->ctx_no = alloc.ctx_no;
	domain->pgtable = pgtable;

	domain->domain.geometry = (struct iommu_domain_geometry){
		.aperture_start = 0,
		.aperture_end = caps.max_iova_addr,
		.force_aperture = true,
	};

	return &domain->domain;
}

static struct iommu_device *xen_iommu_probe_device(struct device *dev)
{
	if (!dev_is_pci(dev))
		return ERR_PTR(-ENODEV);

	return &xen_iommu_device;
}

static int xen_iommu_map_pages(struct iommu_domain *domain, unsigned long iova,
			       phys_addr_t paddr, size_t pgsize, size_t pgcount,
			       int prot, gfp_t gfp, size_t *mapped)
{
	int ret = 0;
	size_t _mapped; /* for pgtable callback */
	struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
	struct pv_iommu_map_pages map = {
		.ctx_no = dom->ctx_no,
		.pgsize = pgsize,
		.map_flags = 0,
		.mapped = 0,
	};

	/* NOTE: paddr is actually bound to pfn, not gfn */
	uint64_t pfn0 = addr_to_pfn(paddr);
	uint64_t dfn0 = addr_to_pfn(iova);

	if (prot & IOMMU_READ)
		map.map_flags |= IOMMU_MAP_readable;

	if (prot & IOMMU_WRITE)
		map.map_flags |= IOMMU_MAP_writeable;

	if (prot & IOMMU_CACHE)
		map.map_flags |= IOMMU_MAP_cache;

	if (map_single_pages) {
		size_t i = 0;
		map.nr_pages = 1;

		for (; i < pgcount; i++) {
			map.gfn = pfn_to_gfn(pfn0 + i);
			map.dfn = dfn0 + i;
			map.nr_pages = 1;

			ret = HYPERVISOR_iommu_op(IOMMU_map_pages, &map);

			if (ret)
				break;
		}
	} else {
		map.nr_pages = pgcount;
		map.gfn = pfn_to_gfn(pfn0);
		map.dfn = dfn0;

		ret = HYPERVISOR_iommu_op(IOMMU_map_pages, &map);
	}

	if (mapped)
		*mapped = pgsize * map.mapped;

	dom->pgtable->map_pages(dom->pgtable, iova, paddr, pgsize, pgcount,
				prot, gfp, &_mapped);

	return ret;
}

static size_t xen_iommu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
				    size_t pgsize, size_t pgcount,
				    struct iommu_iotlb_gather *iotlb_gather)
{
	struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
	struct pv_iommu_unmap_pages unmap = {
		.ctx_no = dom->ctx_no,
		.pgsize = pgsize,
		.unmapped = 0,
		.nr_pages = pgcount,
		.dfn = addr_to_pfn(iova),
	};

	WARN_ON(HYPERVISOR_iommu_op(IOMMU_unmap_pages, &unmap));
	dom->pgtable->unmap_pages(dom->pgtable, iova, pgsize, pgcount,
				  iotlb_gather);

	return unmap.unmapped * pgsize;
}

static int xen_iommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct pci_dev *pdev;
	struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
	struct pv_iommu_reattach_device reattach = {
		.ctx_no = dom->ctx_no,
		.pasid = 0,
	};

	pdev = to_pci_dev(dev);

	reattach.dev.seg = pci_domain_nr(pdev->bus);
	reattach.dev.bus = pdev->bus->number;
	reattach.dev.devfn = pdev->devfn;

	return HYPERVISOR_iommu_op(IOMMU_reattach_device, &reattach);
}

static void xen_iommu_free(struct iommu_domain *domain)
{
	int ret;
	struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
	struct pv_iommu_free op = {
		.ctx_no = dom->ctx_no,
		.free_flags = 0,
	};

	ret = HYPERVISOR_iommu_op(IOMMU_free_context, &op);

	if (ret)
		pr_err("Context %hu destruction failure\n", dom->ctx_no);

	free_io_pgtable_ops(dom->pgtable);

	kfree(domain);
}

static phys_addr_t xen_iommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);

	if (!dom->ctx_no)
		/* If default domain is identity, phys_addr is iova. */
		return (caps.cap_flags & IOMMUCAP_default_identity) ? iova : 0;
	
	return dom->pgtable->iova_to_phys(dom->pgtable, iova);
}

static void xen_iommu_get_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *reg;
	struct xen_reserved_device_memory *entries;
	struct xen_reserved_device_memory_map map;
	struct pci_dev *pdev;
	int ret, i;

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

	if (ret != -ENOBUFS) {
		pr_err("Unable to get reserved region count (%d)\n", ret);
		return;
	}

	/* Assume a reasonable number of entries, otherwise, something is probably wrong */
	if (WARN_ON(map.nr_entries > 256))
		pr_warn("Xen reporting many reserved regions (%u)\n", map.nr_entries);

	/* And finally get actual mappings */
	entries = kcalloc(map.nr_entries, sizeof(struct xen_reserved_device_memory),
					  GFP_KERNEL);

	if (!entries) {
		pr_err("No memory for map entries\n");
		return;
	}

	map.buffer = entries;

	ret = HYPERVISOR_memory_op(XENMEM_reserved_device_memory_map, &map);

	if (ret != 0) {
		pr_err("Unable to get reserved regions (%d)\n", ret);
		kfree(entries);
		return;
	}

	for (i = 0; i < map.nr_entries; i++) {
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
	.identity_domain = &xen_iommu_identity_domain.domain,
	.release_domain = &xen_iommu_identity_domain.domain,
	.capable = xen_iommu_capable,
	.domain_alloc_paging = xen_iommu_domain_alloc_paging,
	.probe_device = xen_iommu_probe_device,
	.device_group = pci_device_group,
	.get_resv_regions = xen_iommu_get_resv_regions,
	.pgsize_bitmap = XEN_PAGE_SIZE,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.map_pages = xen_iommu_map_pages,
		.unmap_pages = xen_iommu_unmap_pages,
		.attach_dev = xen_iommu_attach_dev,
		.iova_to_phys = xen_iommu_iova_to_phys,
		.free = xen_iommu_free,
	},
};

static int __init xen_iommu_init(void)
{
	long ret;

	if (!xen_domain())
		return -ENODEV;

	/* Check if iommu_op is supported */
	if ((ret = HYPERVISOR_iommu_op(IOMMU_query_capabilities, &caps)))
	{
		pr_err("Unable to query capabilities (%ld)", ret);
		return -ENODEV; /* No Xen IOMMU hardware */
	}

	/* If ctx_no is zero, it may be due to PV-IOMMU not being initialized. */
	if (!caps.max_ctx_no)
	{
		/* Try to initialize PV-IOMMU */
		struct pv_iommu_init init;

		pr_info("Got no usable context, try initializing PV-IOMMU\n");

		/* FIXME: Don't hardcode this */
		init.max_ctx_no = 128;
		init.arena_order = 12;

		pr_info("init.max_ctx_no=%hu\n", init.max_ctx_no);
		pr_info("init.arena_order=%hu\n", init.arena_order);

		/* Try to initialize PV-IOMMU */
		ret = HYPERVISOR_iommu_op(IOMMU_init, &init);

		if (ret == -EACCES) {
			/* PV-IOMMU being already initialized often means not allowed. */
			pr_warn("PV-IOMMU is already initialized, guest may not be allowed to use PV-IOMMU\n");
			return -EACCES;
		} else if (ret) {
			pr_err("PV-IOMMU initialization failure (%ld)", ret);
			return ret;
		}

		WARN_ON(HYPERVISOR_iommu_op(IOMMU_query_capabilities, &caps));
	}

	pr_info("Initialising Xen IOMMU driver\n");
	pr_info("max_ctx_no=%hu\n", caps.max_ctx_no);
	pr_info("max_iova_addr=%llx\n", caps.max_iova_addr);
	pr_info("pgsize_mask=%d\n", caps.pgsize_mask);
	pr_info("default_identity=%c\n", (caps.cap_flags & IOMMUCAP_default_identity) ? 'y' : 'n');
	pr_info("cache=%c\n", (caps.cap_flags & IOMMUCAP_cache) ? 'y' : 'n');

	if (caps.max_ctx_no == 0) {
		pr_err("Unable to use IOMMU PV driver (no context available ?)\n");
		return -ENOTSUPP; /* Unable to use IOMMU PV ? */
	}

	xen_iommu_ops.pgsize_bitmap = caps.pgsize_mask;

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
		map_single_pages = true;

	/* Initialize identity domain */
	xen_iommu_identity_domain.ctx_no = 0;

	xen_iommu_identity_domain.domain.geometry = (struct iommu_domain_geometry){
		.aperture_start = 0,
		.aperture_end = caps.max_iova_addr,
		.force_aperture = true,
	};

	ret = iommu_device_sysfs_add(&xen_iommu_device, NULL, NULL, "xen-iommu");
	if (ret) {
		pr_err("Unable to add Xen IOMMU sysfs\n");
		return ret;
	}

	ret = iommu_device_register(&xen_iommu_device, &xen_iommu_ops, NULL);
	if (ret) {
		pr_err("Unable to register Xen IOMMU device %ld\n", ret);
		iommu_device_sysfs_remove(&xen_iommu_device);
		return ret;
	}

	return 0;
}

module_init(xen_iommu_init);
