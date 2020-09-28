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
	struct device *dev = &ddev->dev;
	struct platform_device_info pdevinfo = { 0 };
	struct uio_info uio_pdata = { 0 };
	struct platform_device *uio_pdev;
	struct resource *res;
	int i;

	pdevinfo.name = "uio_pdrv_genirq";

	res = kcalloc(ddev->num_irqs + 1, sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res[0].parent = &ddev->mmio_res;
	res[0].flags = IORESOURCE_MEM;
	res[0].start = ddev->mmio_res.start;
	res[0].end = ddev->mmio_res.end;

	/* then add irq resource */
	for (i = 0; i < ddev->num_irqs; i++) {
		res[i + 1].flags = IORESOURCE_IRQ;
		res[i + 1].start = ddev->irqs[i];
		res[i + 1].end = ddev->irqs[i];
	}

	uio_pdata.name = DRIVER_NAME;
	uio_pdata.version = "0";

	pdevinfo.res = res;
	pdevinfo.num_res = ddev->num_irqs + 1;
	pdevinfo.parent = &ddev->dev;
	pdevinfo.id = PLATFORM_DEVID_AUTO;
	pdevinfo.data = &uio_pdata;
	pdevinfo.size_data = sizeof(uio_pdata);

	uio_pdev = platform_device_register_full(&pdevinfo);
	if (!IS_ERR(uio_pdev))
		dev_set_drvdata(dev, uio_pdev);

	kfree(res);

	return PTR_ERR_OR_ZERO(uio_pdev);
}

static void dfl_uio_pdev_remove(struct dfl_device *ddev)
{
	struct platform_device *uio_pdev = dev_get_drvdata(&ddev->dev);

	platform_device_unregister(uio_pdev);
}

static struct dfl_driver dfl_uio_pdev_driver = {
	.drv	= {
		.name       = DRIVER_NAME,
	},
	.probe	= dfl_uio_pdev_probe,
	.remove	= dfl_uio_pdev_remove,
};
module_dfl_driver(dfl_uio_pdev_driver);

MODULE_DESCRIPTION("DFL driver for Userspace I/O platform devices");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
