// SPDX-License-Identifier: GPL-2.0

/* Intel(R) Memory based QSFP driver for platform devices.
 *
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
 */

#include <linux/phy/qsfp-mem.h>
#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/processor.h>
#include <linux/slab.h>

#define INTEL_QSFP_MEM_CONTROLLER_NAME "qsfp-mem-ctrl"

static int qsfp_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *region = NULL;
	struct resource *qsfpconfig = NULL;
	struct qsfp *qsfp = NULL;
	int ret = 0;

	qsfp = devm_kzalloc(dev, sizeof(*qsfp), GFP_KERNEL);
	if (!qsfp)
		return -ENOMEM;

	qsfp->dev = dev;
	mutex_init(&qsfp->lock);
	platform_set_drvdata(pdev, qsfp);

	/* QSFP Mem address space */
	qsfpconfig = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						  INTEL_QSFP_MEM_CONTROLLER_NAME);
	if (!qsfpconfig) {
		dev_err(dev, "resource %s not defined\n", INTEL_QSFP_MEM_CONTROLLER_NAME);
		return -ENODEV;
	}

	region = devm_request_mem_region(dev, qsfpconfig->start,
					 resource_size(qsfpconfig), dev_name(dev));
	if (!region) {
		dev_err(dev, "unable to request %s\n", INTEL_QSFP_MEM_CONTROLLER_NAME);
		return -EBUSY;
	}
	qsfp->base = devm_ioremap(dev, region->start, resource_size(region));
	if (!(qsfp->base)) {
		dev_err(dev, "ioremap of %s failed!", INTEL_QSFP_MEM_CONTROLLER_NAME);
		return -ENOMEM;
	}

	ret = qsfp_init_work(qsfp);
	if (ret != 0) {
		dev_err(dev, "Failed to initialize delayed work to read QSFP\n");
		return ret;
	}

	return qsfp_register_regmap(qsfp);
}

static int qsfp_platform_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qsfp *qsfp = dev_get_drvdata(dev);

	qsfp_remove_device(qsfp);
	return 0;
}

static const struct of_device_id intel_fpga_qsfp_mem_ids[] = {
	{ .compatible = "intel,qsfp-mem",
		.data = NULL, },
	{},
};
MODULE_DEVICE_TABLE(of, intel_fpga_qsfp_mem_ids);

static struct platform_driver qsfp_driver = {
	.probe      = qsfp_platform_probe,
	.remove     = qsfp_platform_remove,
	.suspend    = NULL,
	.resume     = NULL,
	.driver     = {
		.name   = "intel,qsfp-mem",
		.owner  = THIS_MODULE,
		.of_match_table = intel_fpga_qsfp_mem_ids,
	},
};

module_platform_driver(qsfp_driver);
MODULE_DESCRIPTION("Intel(R) Memory based QSFP Platform driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");

