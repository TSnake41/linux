/*
 * Xen driver for the paravirtualized IOMMU
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
#include <asm/iommu.h>
#include <asm/string.h>
#include <linux/device/driver.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/stddef.h>

#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/physdev.h>
#include <xen/interface/pv-iommu.h>
#include <asm/xen/hypercall.h>

//#include "dma-iommu.h"

MODULE_DESCRIPTION("Xen IOMMU driver");
MODULE_AUTHOR("Teddy Astie <teddy.astie@vates.tech>");
MODULE_LICENSE("GPL");

#define MSI_RANGE_START         (0xfee00000)
#define MSI_RANGE_END           (0xfeefffff)

#define XEN_IOMMU_PGSIZES       (~0xFFFUL)

#define MAX_REQS   0x8000

struct xen_iommu_domain {
    struct iommu_domain domain;
    
    u16 ctx_no;
};

static struct iommu_device xen_iommu_device;

static inline struct xen_iommu_domain *to_xen_iommu_domain(struct iommu_domain *dom)
{
    return container_of(dom, struct xen_iommu_domain, domain);
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
    } else {
        /* use default domain */
        ctx_no = 0;
    }

    domain = kzalloc(sizeof(*domain), GFP_KERNEL);

    domain->ctx_no = ctx_no;

    domain->domain.geometry.aperture_start = 0;
    domain->domain.geometry.aperture_end = ~0;
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

void xen_iommu_release_device(struct device *dev)
{
    int ret;
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_reattach_device,
        .flags = 0,
        .ctx_no = 0 /* reattach device back to default context */
    };

    if (!dev_is_pci(dev))
        return;

    struct pci_dev *pdev = to_pci_dev(dev);

    op.reattach_device.dev.seg = pci_domain_nr(pdev->bus);
    op.reattach_device.dev.bus = pdev->bus->number;
    op.reattach_device.dev.devfn = pdev->devfn;

    ret = HYPERVISOR_iommu_op(&op, 1);

    if (ret) {
        pr_warn("Unable to release device %p", &op.reattach_device.dev);
    }
}

int xen_iommu_map_pages(struct iommu_domain *domain, unsigned long iova,
                        phys_addr_t paddr, size_t pgsize, size_t pgcount,
			            int prot, gfp_t gfp, size_t *mapped)
{
    /* TODO: better handling, batching, ... */
    size_t count = (pgsize / 0x1000) * pgcount;
    size_t i;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_map_page,
        .flags = 0,
        .ctx_no = dom->ctx_no
    };

    if (WARN(!dom->ctx_no, "Tried to map page to default context")) {
        return -EINVAL;
    }

    pr_info("Mapping to %lu %zu %zu", iova, pgsize, pgcount);

    if (prot & IOMMU_READ)
        op.flags |= IOMMU_OP_readable;

    if (prot & IOMMU_WRITE)
        op.flags |= IOMMU_OP_writeable;

    for (i = 0; i < count; ++i) {
        op.map_page.gfn = paddr >> XEN_PAGE_SHIFT;
        op.map_page.dfn = iova >> XEN_PAGE_SHIFT;

        int ret = HYPERVISOR_iommu_op(&op, 1);

        if (ret) {
            pr_err("Map operation failed for context %hu (%d)", dom->ctx_no, ret);
        } else if (mapped) {
            *mapped += 1;
        }
    }

    return 0;
}

size_t xen_iommu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
			                 size_t pgsize, size_t pgcount,
			                 struct iommu_iotlb_gather *iotlb_gather)
{
    /* TODO: better handling, batching, ... */
    size_t count = (pgsize / 0x1000) * pgcount;
    size_t i, unmapped;
    struct xen_iommu_domain *dom = to_xen_iommu_domain(domain);
    struct pv_iommu_op op = {
        .subop_id = IOMMUOP_unmap_page,
        .ctx_no = dom->ctx_no,
        .flags = 0,
    };
    
    if (WARN(!dom->ctx_no, "Tried to unmap page to default context")) {
        return -EINVAL;
    }


    for (i = 0; i < count; ++i) {
        op.unmap_page.dfn = iova >> XEN_PAGE_SHIFT;

        int ret = HYPERVISOR_iommu_op(&op, 1);

        if (ret) {
            pr_err("Unmap operation failed for context %hu (%d)", dom->ctx_no, ret);
        } else {
            unmapped++;
        }
    }

    return unmapped;
}

int xen_iommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
    int ret;
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

        ret = HYPERVISOR_iommu_op(&op, 1);

        if (ret) {
            pr_err("Context %hu destruction failure", dom->ctx_no);
        }
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

    op.lookup_page.dfn = iova >> XEN_PAGE_SHIFT;
    
    ret = HYPERVISOR_iommu_op(&op, 1);

    if (ret)
        return 0;

    phys_addr_t page_addr = (op.lookup_page.gfn << XEN_PAGE_SHIFT);

    /* Consider iova offset */
    return page_addr + (iova & 0xFFF);
}

static struct iommu_ops xen_iommu_ops = {
    .capable = xen_iommu_capable,
    .domain_alloc = xen_iommu_domain_alloc,
    .probe_device = xen_iommu_probe_device,
    .device_group = xen_iommu_device_group,
    .release_device = xen_iommu_release_device,
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

	if (!xen_domain())
		return -ENODEV;

    if (!xen_initial_domain())
        return -EPERM;

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

    return 0;
}

void __exit xen_iommu_fini(void)
{
	pr_info("Unregistering Xen IOMMU driver\n");
    
    /* TOOD: needs cleanup ? */
    iommu_device_unregister(&xen_iommu_device);
    iommu_device_sysfs_remove(&xen_iommu_device);
}

module_init(xen_iommu_init);
module_exit(xen_iommu_fini);