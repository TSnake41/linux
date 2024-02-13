/*
 * Xen driver for the paravirtualized IOMMU
 *
 */
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

#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/pv-iommu.h>
#include <asm/xen/hypercall.h>

//#include "dma-iommu.h"

#define MSI_RANGE_START         (0xfee00000)
#define MSI_RANGE_END           (0xfeefffff)

#define XEN_IOMMU_PGSIZES       (~0xFFFUL)

#define MAX_REQS   0x8000

struct xen_iommu {
    struct iommu_device device;
};

struct xen_iommu_domain {
    struct iommu_domain domain;
    
    u16 ctx_no;
};

static struct xen_iommu xen_iommu_device;

static int xen_iommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
    if (!dev_is_pci(dev))
        return -EINVAL;

    /* TODO */
    return 0;
}

struct iommu_domain_ops xen_iommu_domain_ops = {
    .attach_dev = xen_iommu_attach_dev,
};

static bool xen_iommu_capable(struct device *dev, enum iommu_cap cap)
{
    /* No specific iommu_cap */
    return false;
}

static struct iommu_domain *xen_iommu_domain_alloc(unsigned type)
{
    struct xen_iommu_domain *domain;
    int ret;

    struct pv_iommu_op op = {
        .ctx_no = 0,
        .flags = 0,
        .subop_id = IOMMUOP_alloc_context
    };
    
    if (!(type & IOMMU_DOMAIN_IDENTITY))
        op.flags |= IOMMU_CREATE_clone;

    ret = HYPERVISOR_iommu_op(&op, 1);

    if (!ret)
        return NULL;

    domain = kzalloc(sizeof(*domain), GFP_KERNEL);

    domain->ctx_no = op.ctx_no;

    domain->domain.geometry.aperture_start = 0;
    domain->domain.geometry.aperture_end = ~0;
    domain->domain.geometry.force_aperture = true;

    return &domain->domain;
}

struct iommu_ops xen_iommu_ops = {
    .capable = xen_iommu_capable,
    .domain_alloc = xen_iommu_domain_alloc,
};

static int __init xen_iommu_init(void)
{
	if (!xen_domain())
		return -ENODEV;

    if (!xen_initial_domain())
        return -EPERM;

	pr_info("Initialising Xen IOMMU driver\n");

    memset(&xen_iommu_device, 0, sizeof(xen_iommu_device));
    xen_iommu_device.device.ops = &xen_iommu_ops;

    return iommu_device_register(&xen_iommu_device.device, &xen_iommu_ops, NULL);
}

static void __exit xen_iommu_fini(void)
{
	pr_info("Unregistering Xen IOMMU driver\n");

    /* TOOD: Cleanup ? */
    iommu_device_unregister(&xen_iommu_device.device);
}

module_init(xen_iommu_init);
module_exit(xen_iommu_fini);

MODULE_DESCRIPTION("Xen IOMMU driver");
MODULE_AUTHOR("Teddy Astie <teddy.astie@vates.tech>");
MODULE_LICENSE("GPL");