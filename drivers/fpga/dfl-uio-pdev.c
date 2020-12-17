// SPDX-License-Identifier: GPL-2.0
/*
 * DFL driver for Userspace I/O platform devices
 *
 * Copyright (C) 2020 Intel Corporation, Inc.
 */
#include <linux/dfl.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>

#define DRIVER_NAME "dfl-uio-pdev"

static int dfl_uio_pdev_probe(struct dfl_device *ddev)
{
	struct platform_device_info pdevinfo = { 0 };
	struct resource res[2] = { { 0 } };
	struct uio_info uio_pdata = { 0 };
	struct platform_device *uio_pdev;
	struct device *dev = &ddev->dev;
	unsigned int num_res = 1;

	res[0].parent = &ddev->mmio_res;
	res[0].flags = IORESOURCE_MEM;
	res[0].start = ddev->mmio_res.start;
	res[0].end = ddev->mmio_res.end;

	if (ddev->num_irqs) {
		if (ddev->num_irqs > 1)
			dev_warn(&ddev->dev,
				 "%d irqs for %s, but UIO only supports the first one\n",
				 ddev->num_irqs, dev_name(&ddev->dev));

		res[1].flags = IORESOURCE_IRQ;
		res[1].start = ddev->irqs[0];
		res[1].end = ddev->irqs[0];
		num_res++;
	}

	uio_pdata.name = DRIVER_NAME;
	uio_pdata.version = "0";

	pdevinfo.name = "uio_pdrv_genirq";
	pdevinfo.res = res;
	pdevinfo.num_res = num_res;
	pdevinfo.parent = &ddev->dev;
	pdevinfo.id = PLATFORM_DEVID_AUTO;
	pdevinfo.data = &uio_pdata;
	pdevinfo.size_data = sizeof(uio_pdata);

	uio_pdev = platform_device_register_full(&pdevinfo);
	if (!IS_ERR(uio_pdev))
		dev_set_drvdata(dev, uio_pdev);

	return PTR_ERR_OR_ZERO(uio_pdev);
}

static void dfl_uio_pdev_remove(struct dfl_device *ddev)
{
	struct platform_device *uio_pdev = dev_get_drvdata(&ddev->dev);

	platform_device_unregister(uio_pdev);
}

#define FME_FEATURE_ID_ETH_GROUP	0x10

static const struct dfl_device_id dfl_uio_pdev_ids[] = {
	{ FME_ID, FME_FEATURE_ID_ETH_GROUP },

	/* Add your new id entries here to support uio for more dfl features */

	{ }
};
MODULE_DEVICE_TABLE(dfl, dfl_uio_pdev_ids);

static struct dfl_driver dfl_uio_pdev_driver = {
	.drv	= {
		.name       = DRIVER_NAME,
	},
	.id_table = dfl_uio_pdev_ids,
	.probe	= dfl_uio_pdev_probe,
	.remove	= dfl_uio_pdev_remove,
};
module_dfl_driver(dfl_uio_pdev_driver);

MODULE_DESCRIPTION("DFL driver for Userspace I/O platform devices");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
