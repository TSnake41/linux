// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic page table allocator for tracking purposes.
 * Based on AMD IO pagetable allocator v2.
 *
 * Copyright (C) 2024 Vates SAS
 * Author: Teddy Astie <teddy.astie@vates.tech>
 */

#define pr_fmt(fmt)	"xen-iommu pg-table: " fmt
#define dev_fmt(fmt)	pr_fmt(fmt)

#include <linux/bitops.h>
#include <linux/io-pgtable.h>
#include <linux/kernel.h>

#include <asm/barrier.h>

#include "iommu-pages.h"

#include "xen/page.h"

#define IOMMU_PAGE_PRESENT	BIT_ULL(0)	/* Is present */
#define IOMMU_PAGE_HUGE		BIT_ULL(1)	/* Is hugepage */
#define MAX_PTRS_PER_PAGE	512

#define IOMMU_PAGE_SIZE_2M	BIT_ULL(21)
#define IOMMU_PAGE_SIZE_1G	BIT_ULL(30)

#define PM_ADDR_MASK		0x000ffffffffff000ULL
#define XEN_IOMMU_PGSIZES	(XEN_PAGE_SIZE | (1ULL << 21) | (1ULL << 30))

#define PAGE_MODE_NONE    0x00
#define PAGE_MODE_1_LEVEL 0x01
#define PAGE_MODE_2_LEVEL 0x02
#define PAGE_MODE_3_LEVEL 0x03
#define PAGE_MODE_4_LEVEL 0x04
#define PAGE_MODE_5_LEVEL 0x05

#define IOMMU_PTE_PR BIT(0)
#define IOMMU_PTE_PRESENT(pte) ((pte) & IOMMU_PTE_PR)

#define PM_LEVEL_SHIFT(x)	(12 + ((x) * 9))
#define PM_LEVEL_INDEX(x, a)	(((a) >> PM_LEVEL_SHIFT((x))) & 0x1ffULL)

#define IOMMU_IN_ADDR_BIT_SIZE  52
#define IOMMU_OUT_ADDR_BIT_SIZE 52

#define PAGE_SIZE_ALIGN(address, pagesize) \
		((address) & ~((pagesize) - 1))

#define io_pgtable_to_data(x) \
	container_of((x), struct xen_io_pgtable, iop)

#define io_pgtable_ops_to_data(x) \
	io_pgtable_to_data(io_pgtable_ops_to_pgtable(x))


struct xen_io_pgtable {
	struct io_pgtable_cfg	pgtbl_cfg;
	struct io_pgtable	iop;
	u64			*pgd;	/* pgtable pgd pointer */
};

static inline bool is_large_pte(u64 pte)
{
	return (pte & IOMMU_PAGE_HUGE);
}

static inline u64 set_pgtable_attr(u64 *page)
{
	return (virt_to_phys(page) | IOMMU_PAGE_PRESENT);
}

static inline void *get_pgtable_pte(u64 pte)
{
	return phys_to_virt(pte & PM_ADDR_MASK);
}

static u64 set_pte_attr(u64 paddr, u64 pg_size)
{
	u64 pte;

	pte = paddr & PM_ADDR_MASK;
	pte |= IOMMU_PAGE_PRESENT;

	/* Large page */
	if (pg_size == IOMMU_PAGE_SIZE_1G || pg_size == IOMMU_PAGE_SIZE_2M)
		pte |= IOMMU_PAGE_HUGE;

	return pte;
}

static inline u64 get_alloc_page_size(u64 size)
{
	if (size >= IOMMU_PAGE_SIZE_1G)
		return IOMMU_PAGE_SIZE_1G;

	if (size >= IOMMU_PAGE_SIZE_2M)
		return IOMMU_PAGE_SIZE_2M;

	return XEN_PAGE_SIZE;
}

static inline int page_size_to_level(u64 pg_size)
{
	if (pg_size == IOMMU_PAGE_SIZE_1G)
		return PAGE_MODE_3_LEVEL;
	if (pg_size == IOMMU_PAGE_SIZE_2M)
		return PAGE_MODE_2_LEVEL;

	return PAGE_MODE_1_LEVEL;
}

static void free_pgtable(u64 *pt, int level)
{
	u64 *p;
	int i;

	for (i = 0; i < MAX_PTRS_PER_PAGE; i++) {
		/* PTE present? */
		if (!IOMMU_PTE_PRESENT(pt[i]))
			continue;

		if (is_large_pte(pt[i]))
			continue;

		/*
		 * Free the next level. No need to look at l1 tables here since
		 * they can only contain leaf PTEs; just free them directly.
		 */
		p = get_pgtable_pte(pt[i]);
		if (level > 2)
			free_pgtable(p, level - 1);
		else
			iommu_free_page(p);
	}

	iommu_free_page(pt);
}

/* Allocate page table */
static u64 *xen_alloc_pte(u64 *pgd, unsigned long iova, gfp_t gfp,
			  unsigned long pg_size, bool *updated)
{
	u64 *pte, *page;
	int level, end_level;

	level = PAGE_MODE_5_LEVEL - 1;
	end_level = page_size_to_level(pg_size);
	pte = &pgd[PM_LEVEL_INDEX(level, iova)];
	iova = PAGE_SIZE_ALIGN(iova, XEN_PAGE_SIZE);

	while (level >= end_level) {
		u64 __pte, __npte;

		__pte = *pte;

		if (IOMMU_PTE_PRESENT(__pte) && is_large_pte(__pte)) {
			/* Unmap large pte */
			cmpxchg64(pte, *pte, 0ULL);
			*updated = true;
			continue;
		}

		if (!IOMMU_PTE_PRESENT(__pte)) {
			page = iommu_alloc_page(gfp);
			if (!page)
				return NULL;

			__npte = set_pgtable_attr(page);
			/* pte could have been changed somewhere. */
			if (cmpxchg64(pte, __pte, __npte) != __pte)
				iommu_free_page(page);
			else if (IOMMU_PTE_PRESENT(__pte))
				*updated = true;

			continue;
		}

		level -= 1;
		pte = get_pgtable_pte(__pte);
		pte = &pte[PM_LEVEL_INDEX(level, iova)];
	}

	/* Tear down existing pte entries */
	if (IOMMU_PTE_PRESENT(*pte)) {
		u64 *__pte;

		*updated = true;
		__pte = get_pgtable_pte(*pte);
		cmpxchg64(pte, *pte, 0ULL);
		if (pg_size == IOMMU_PAGE_SIZE_1G)
			free_pgtable(__pte, end_level - 1);
		else if (pg_size == IOMMU_PAGE_SIZE_2M)
			iommu_free_page(__pte);
	}

	return pte;
}

/*
 * This function checks if there is a PTE for a given dma address.
 * If there is one, it returns the pointer to it.
 */
static u64 *fetch_pte(struct xen_io_pgtable *pgtable, unsigned long iova,
		      unsigned long *page_size)
{
	u64 *pte;
	int level;

	level = PAGE_MODE_5_LEVEL - 1;
	pte = &pgtable->pgd[PM_LEVEL_INDEX(level, iova)];
	/* Default page size is 4K */
	*page_size = XEN_PAGE_SIZE;

	while (level) {
		/* Not present */
		if (!IOMMU_PTE_PRESENT(*pte))
			return NULL;

		/* Walk to the next level */
		pte = get_pgtable_pte(*pte);
		pte = &pte[PM_LEVEL_INDEX(level - 1, iova)];

		/* Large page */
		if (is_large_pte(*pte)) {
			if (level == PAGE_MODE_3_LEVEL)
				*page_size = IOMMU_PAGE_SIZE_1G;
			else if (level == PAGE_MODE_2_LEVEL)
				*page_size = IOMMU_PAGE_SIZE_2M;
			else
				return NULL;	/* Wrongly set PSE bit in PTE */

			break;
		}

		level -= 1;
	}

	return pte;
}

static int iommu_xen_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
			       phys_addr_t paddr, size_t pgsize, size_t pgcount,
			       int prot, gfp_t gfp, size_t *mapped)
{
	struct xen_io_pgtable *pgtable = io_pgtable_ops_to_data(ops);	
	struct io_pgtable_cfg *cfg = &pgtable->pgtbl_cfg;
	u64 *pte;
	unsigned long map_size;
	unsigned long mapped_size = 0;
	size_t size = pgcount << __ffs(pgsize);
	int ret = 0;
	bool updated = false;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize) || !pgcount)
		return -EINVAL;

	while (mapped_size < size) {
		map_size = get_alloc_page_size(pgsize);
		pte = xen_alloc_pte(pgtable->pgd, iova, gfp, map_size, &updated);
		if (!pte) {
			ret = -ENOMEM;
			goto out;
		}

		*pte = set_pte_attr(paddr, map_size);

		iova += map_size;
		paddr += map_size;
		mapped_size += map_size;
	}

out:
	if (mapped)
		*mapped += mapped_size;

	return ret;
}

static unsigned long iommu_xen_unmap_pages(struct io_pgtable_ops *ops,
					   unsigned long iova,
					   size_t pgsize, size_t pgcount,
					   struct iommu_iotlb_gather *gather)
{
	struct xen_io_pgtable *pgtable = io_pgtable_ops_to_data(ops);
	struct io_pgtable_cfg *cfg = &pgtable->iop.cfg;
	unsigned long unmap_size;
	unsigned long unmapped = 0;
	size_t size = pgcount << __ffs(pgsize);
	u64 *pte;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize || !pgcount))
		return 0;

	while (unmapped < size) {
		pte = fetch_pte(pgtable, iova, &unmap_size);
		if (!pte)
			return unmapped;

		*pte = 0ULL;

		iova = (iova & ~(unmap_size - 1)) + unmap_size;
		unmapped += unmap_size;
	}

	return unmapped;
}

static phys_addr_t iommu_xen_iova_to_phys(struct io_pgtable_ops *ops, unsigned long iova)
{
	struct xen_io_pgtable *pgtable = io_pgtable_ops_to_data(ops);
	unsigned long offset_mask, pte_pgsize;
	u64 *pte, __pte;

	pte = fetch_pte(pgtable, iova, &pte_pgsize);
	if (!pte || !IOMMU_PTE_PRESENT(*pte))
		return 0;

	offset_mask = pte_pgsize - 1;
	__pte = *pte & PM_ADDR_MASK;

	return (__pte & ~offset_mask) | (iova & offset_mask);
}

static void xen_free_pgtable(struct io_pgtable *iop)
{
	struct xen_io_pgtable *pgtable = container_of(iop, struct xen_io_pgtable, iop);

	if (!pgtable || !pgtable->pgd)
		return;

	/* Free page table */
	free_pgtable(pgtable->pgd, PAGE_MODE_5_LEVEL);
	kfree(pgtable);
}

static struct io_pgtable *xen_alloc_pgtable(struct io_pgtable_cfg *cfg, void *cookie)
{
	struct xen_io_pgtable *pgtable = kmalloc(sizeof(struct xen_io_pgtable),
						 GFP_KERNEL);
	if (!pgtable)
		return NULL;

	pgtable->pgd = iommu_alloc_page(GFP_KERNEL);
	if (!pgtable->pgd) {
		kfree(pgtable);
		return NULL;
	}

	pgtable->iop.ops.map_pages    = iommu_xen_map_pages;
	pgtable->iop.ops.unmap_pages  = iommu_xen_unmap_pages;
	pgtable->iop.ops.iova_to_phys = iommu_xen_iova_to_phys;

	cfg->pgsize_bitmap = XEN_IOMMU_PGSIZES;
	cfg->ias           = IOMMU_IN_ADDR_BIT_SIZE;
	cfg->oas           = IOMMU_OUT_ADDR_BIT_SIZE;

	pgtable->pgtbl_cfg = *cfg;

	return &pgtable->iop;
}

struct io_pgtable_init_fns io_pgtable_xen_init_fns = {
	.alloc	= xen_alloc_pgtable,
	.free	= xen_free_pgtable,
};
