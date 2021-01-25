// SPDX-License-Identifier: GPL-2.0
/*
 * Generic DFL driver for Userspace I/O devicess
 *
 * Copyright (C) 2021 Intel Corporation, Inc.
 */
#include <linux/dfl.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/uio_driver.h>

#define DRIVER_NAME "uio_dfl"

struct uio_dfl_dev {
	struct device *dev;
	struct uio_info uioinfo;
	spinlock_t lock;	/* Serializes the irq handler and irqcontrol */
	unsigned long flags;
};

static irqreturn_t uio_dfl_handler(int irq, struct uio_info *uioinfo)
{
	struct uio_dfl_dev *udd = uioinfo->priv;

	/* Just disable the interrupt in the interrupt controller, and
	 * remember the state so we can allow user space to enable it later.
	 */

	spin_lock(&udd->lock);
	if (!__test_and_set_bit(0, &udd->flags))
		disable_irq_nosync(irq);
	spin_unlock(&udd->lock);

	return IRQ_HANDLED;
}

static int uio_dfl_irqcontrol(struct uio_info *uioinfo, s32 irq_on)
{
	struct uio_dfl_dev *udd = uioinfo->priv;
	unsigned long flags;

	/* Allow user space to enable and disable the interrupt
	 * in the interrupt controller, but keep track of the
	 * state to prevent per-irq depth damage.
	 *
	 * Serialize this operation to support multiple tasks and concurrency
	 * with irq handler on SMP systems.
	 */

	spin_lock_irqsave(&udd->lock, flags);
	if (irq_on) {
		if (__test_and_clear_bit(0, &udd->flags))
			enable_irq(uioinfo->irq);
	} else {
		if (!__test_and_set_bit(0, &udd->flags))
			disable_irq_nosync(uioinfo->irq);
	}
	spin_unlock_irqrestore(&udd->lock, flags);

	return 0;
}

static int uio_dfl_probe(struct dfl_device *ddev)
{
	struct resource *r = &ddev->mmio_res;
	struct device *dev = &ddev->dev;
	struct uio_info *uioinfo;
	struct uio_dfl_dev *udd;
	struct uio_mem *uiomem;
	int ret;

	udd = devm_kzalloc(dev, sizeof(*udd), GFP_KERNEL);
	if (!udd)
		return -ENOMEM;

	spin_lock_init(&udd->lock);
	udd->flags = 0; /* interrupt is enabled to begin with */
	udd->dev = &ddev->dev;

	uioinfo = &udd->uioinfo;
	uioinfo->name = DRIVER_NAME;
	uioinfo->version = "0";

	uiomem = &udd->uioinfo.mem[0];
	uiomem->memtype = UIO_MEM_PHYS;
	uiomem->addr = r->start & PAGE_MASK;
	uiomem->offs = r->start & ~PAGE_MASK;
	uiomem->size = (uiomem->offs + resource_size(r)
			+ PAGE_SIZE - 1) & PAGE_MASK;
	uiomem->name = r->name;

	if (ddev->num_irqs) {
		if (ddev->num_irqs > 1)
			dev_warn(dev,
				 "%d irqs for %s, but UIO only supports the first one\n",
				 ddev->num_irqs, dev_name(dev));

		uioinfo->irq = ddev->irqs[0];
	} else {
		uioinfo->irq = UIO_IRQ_NONE;
	}

	if (uioinfo->irq) {
		struct irq_data *irq_data = irq_get_irq_data(uioinfo->irq);

		/*
		 * If a level interrupt, dont do lazy disable. Otherwise the
		 * irq will fire again since clearing of the actual cause, on
		 * device level, is done in userspace
		 * irqd_is_level_type() isn't used since isn't valid until
		 * irq is configured.
		 */
		if (irq_data &&
		    irqd_get_trigger_type(irq_data) & IRQ_TYPE_LEVEL_MASK) {
			dev_dbg(dev, "disable lazy unmask\n");
			irq_set_status_flags(uioinfo->irq, IRQ_DISABLE_UNLAZY);
		}
	}

	uioinfo->handler = uio_dfl_handler;
	uioinfo->irqcontrol = uio_dfl_irqcontrol;
	uioinfo->priv = udd;

	ret = devm_uio_register_device(dev, uioinfo);
	if (ret)
		dev_err(dev, "unable to register uio device\n");

	return ret;
}

#define FME_FEATURE_ID_ETH_GROUP	0x10

static const struct dfl_device_id uio_dfl_ids[] = {
	{ FME_ID, FME_FEATURE_ID_ETH_GROUP },
	{ }
};
MODULE_DEVICE_TABLE(dfl, uio_dfl_ids);

static struct dfl_driver uio_dfl_driver = {
	.drv = {
		.name = DRIVER_NAME,
	},
	.id_table	= uio_dfl_ids,
	.probe		= uio_dfl_probe,
};
module_dfl_driver(uio_dfl_driver);

MODULE_DESCRIPTION("Generic DFL driver for Userspace I/O devices");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
