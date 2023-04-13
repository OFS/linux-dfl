// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for FPGA Device Feature List(DFL) device entry.
 *
 * Copyright (C) 2023 Intel Corp.
 *
 * Authors:
 *   Basheer Ahmed Muddebihal <basheer.ahmed.muddebihal@linux.intel.com>
 */

#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#include "dfl.h"

#define DRV_NAME	"dfl-platform"

struct dfl_platform_drvdata {
	struct dfl_fpga_cdev *cdev;	/* container device */
};

static int dfl_platform_init_drvdata(struct platform_device *pdev)
{
	struct dfl_platform_drvdata *drvdata;

	drvdata = devm_kzalloc(&pdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	platform_set_drvdata(pdev, drvdata);

	return 0;
}

static void dfl_platform_remove_feature_devs(struct platform_device *pdev)
{
	struct dfl_platform_drvdata *drvdata = platform_get_drvdata(pdev);

	/* remove all children feature devices */
	dfl_fpga_feature_devs_remove(drvdata->cdev);
}

static int dfl_platform_process_dfl_node(struct platform_device *pdev,
					 struct dfl_fpga_enum_info *info,
					 struct resource dfl_location)
{
	resource_size_t start, len;
	void __iomem *base;
	int ret = 0;

	start = dfl_location.start;
	len =  resource_size(&dfl_location);

	if (!request_mem_region(start, len, DRV_NAME)) {
		dev_err(&pdev->dev, "cannot claim memory\n");
		return -EINVAL;
	}

	base = of_iomap(pdev->dev.of_node, 0);
	if (!base) {
		dev_err(&pdev->dev, "cannot map memory\n");
		ret = -ENOMEM;
		goto err_map;
	}

	dfl_fpga_enum_info_add_dfl(info, start, len);

	/* release I/O mappings for next step enumeration */
	iounmap(base);
err_map:
	release_mem_region(start, len);

	return ret;
}

/* enumerate feature devices under device */
static int dfl_platform_enumerate_feature_devs(struct platform_device *pdev,
					       struct resource dfl_location)
{
	struct dfl_platform_drvdata *drvdata = platform_get_drvdata(pdev);
	struct dfl_fpga_enum_info *info;
	struct dfl_fpga_cdev *cdev;
	int  ret = 0;

	/* allocate enumeration info */
	info = dfl_fpga_enum_info_alloc(&pdev->dev);
	if (!info)
		return -ENOMEM;

	/* process the device tree node */
	ret = dfl_platform_process_dfl_node(pdev, info, dfl_location);
	if (ret)
		goto info_free_exit;

	/* start enumeration with prepared enumeration information */
	cdev = dfl_fpga_feature_devs_enumerate(info);
	if (IS_ERR(cdev)) {
		dev_err(&pdev->dev, "Enumeration failure\n");
		ret = PTR_ERR(cdev);
		goto info_free_exit;
	}

	drvdata->cdev = cdev;

info_free_exit:
	dfl_fpga_enum_info_free(info);

	return ret;
}

static int dfl_platform_probe(struct platform_device *pdev)
{
	struct resource dfl_location;
	int ret = 0;

	dev_info(&pdev->dev, "DFL Platform probe\n");

	ret = of_address_to_resource(pdev->dev.of_node, 0, &dfl_location);
	if (ret) {
		dev_err_probe(&pdev->dev, ret, "Failed to get DFL location\n");
		return -EINVAL;
	}

	if (dfl_location.start == 0 || dfl_location.end == 0 ||
	    dfl_location.end <= dfl_location.start)
		return -EINVAL;

	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_warn(&pdev->dev, "Couldn't set 64 bit DMA mask, attempting 32\n");
		ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (ret) {
			dev_err_probe(&pdev->dev, ret, "Couldn't set 32 bit DMA mask\n");
			return ret;
		}
	}

	ret = dfl_platform_init_drvdata(pdev);
	if (ret) {
		dev_err_probe(&pdev->dev, ret, "Failed to init drvdata %d.\n", ret);
		return ret;
	}

	ret = dfl_platform_enumerate_feature_devs(pdev, dfl_location);
	if (!ret)
		return ret;

	dev_err_probe(&pdev->dev, ret, "enumeration failure %d.\n", ret);

	return ret;
}

static int dfl_platform_remove(struct platform_device *pdev)
{
	dfl_platform_remove_feature_devs(pdev);
	return 0;
}

static const struct of_device_id dfl_platform_match[] = {
	{ .compatible = "intel,dfl-mmio", },
	{},
};
MODULE_DEVICE_TABLE(of, dfl_platform_match);

static const struct platform_device_id dfl_platform_ids[] = {
	{ DRV_NAME, 0 },
	{ }
};
MODULE_DEVICE_TABLE(platform, dfl_platform_ids);

static struct platform_driver dfl_platform_driver = {
	.probe = dfl_platform_probe,
	.remove = dfl_platform_remove,
	.driver = {
		.name = DRV_NAME,
		.of_match_table = of_match_ptr(dfl_platform_match),
	},
	.id_table = dfl_platform_ids,
};
module_platform_driver(dfl_platform_driver);

MODULE_DESCRIPTION("FPGA DFL Platform Device Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
