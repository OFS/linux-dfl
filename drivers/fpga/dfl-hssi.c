// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for DFL HSSI Configurable Ethernet private feature
 *
 * Copyright 2019-2020 Intel Corporation, Inc.
 */

#include <linux/dfl.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/phy/intel-s10-phy.h>
#include <linux/slab.h>
#include "dfl.h"

/* HSSI Private Feature: Capability - Read-Only */
#define HSSI_CAPABILITY		0x8
#define   DATA_RATE_AVAIL_1G	BIT_ULL(0)
#define   DATA_RATE_AVAIL_10G	BIT_ULL(1)
#define   DATA_RATE_AVAIL_25G	BIT_ULL(2)
#define   DATA_RATE_AVAIL_40G	BIT_ULL(3)
#define   DATA_RATE_AVAIL_50G	BIT_ULL(4)
#define   DATA_RATE_AVAIL_100G	BIT_ULL(5)
#define   DATA_RATE_AVAIL_200G	BIT_ULL(6)
#define   DATA_RATE_AVAIL_400G	BIT_ULL(7)
#define   CONTAINS_PCS_1G	BIT_ULL(8)
#define   CONTAINS_PCS_10G	BIT_ULL(9)
#define   CONTAINS_PCS_25G	BIT_ULL(10)
#define   CONTAINS_PCS_40G	BIT_ULL(11)
#define   CONTAINS_PCS_50G	BIT_ULL(12)
#define   CONTAINS_PCS_100G	BIT_ULL(13)
#define   CONTAINS_PCS_200G	BIT_ULL(14)
#define   CONTAINS_PCS_400G	BIT_ULL(15)
#define   CONTAINS_FEC_1G	BIT_ULL(16)
#define   CONTAINS_FEC_10G	BIT_ULL(17)
#define   CONTAINS_FEC_25G	BIT_ULL(18)
#define   CONTAINS_FEC_40G	BIT_ULL(19)
#define   CONTAINS_FEC_50G	BIT_ULL(20)
#define   CONTAINS_FEC_100G	BIT_ULL(21)
#define   CONTAINS_FEC_200G	BIT_ULL(22)
#define   CONTAINS_FEC_400G	BIT_ULL(23)
#define   DATA_RATE_SWITCH	BIT_ULL(24)
#define   LINK_TRAINING		BIT_ULL(25)
#define   AUTO_NEGOTIATION	BIT_ULL(26)
#define   CONTAINS_MAC		BIT_ULL(27)
#define   NUM_QSFP_INTERFACES	GENMASK_ULL(39, 32)

/* QSFP register space */
#define HSSI_QSFP_BASE		0x10
#define HSSI_QSFP_SIZE		0x20

struct dfl_hssi {
	void __iomem *csr_base;
	struct device *dev;
	unsigned int qsfp_cnt;
	struct platform_device *intel_s10_phy[];
};

static int hssi_create_qsfp(struct dfl_hssi *hssi, struct dfl_device *dfl_dev,
			    int index)
{
	struct intel_s10_platform_data pdata = { 0 };
	struct platform_device_info pdevinfo = { 0 };
	struct platform_device *pdev;

	pdata.csr_base = hssi->csr_base;
	pdata.phy_offset = HSSI_QSFP_BASE + index * HSSI_QSFP_SIZE;

	pdevinfo.name = INTEL_S10_PHY_DRV_NAME;
	pdevinfo.id = PLATFORM_DEVID_AUTO;
	pdevinfo.parent = hssi->dev;
	pdevinfo.data = &pdata;
	pdevinfo.size_data = sizeof(pdata);

	pdev = platform_device_register_full(&pdevinfo);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);

	hssi->qsfp_cnt++;
	hssi->intel_s10_phy[index] = pdev;

	return 0;
}

static void hssi_destroy_qsfp(struct dfl_hssi *hssi, int index)
{
	platform_device_unregister(hssi->intel_s10_phy[index]);
}

static ssize_t capability_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dfl_hssi *hssi = dev_get_drvdata(dev);
	u64 v = readq(hssi->csr_base + HSSI_CAPABILITY);

	return sprintf(buf, "0x%016llx\n", v);
}
static DEVICE_ATTR_RO(capability);

static struct attribute *hssi_attrs[] = {
	&dev_attr_capability.attr,
	NULL,
};
ATTRIBUTE_GROUPS(hssi);

static int dfl_hssi_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct dfl_hssi *hssi;
	int ret, qsfp_cnt, i;
	void __iomem *csr_base;
	u64 v;

	csr_base = devm_ioremap_resource(&dfl_dev->dev, &dfl_dev->mmio_res);
	if (IS_ERR(csr_base)) {
		dev_err(dev, "get mem resource fail!\n");
		return PTR_ERR(csr_base);
	}

	if (!dfl_feature_revision(csr_base)) {
		dev_info(dev, "hssi feature revision 0 not supported\n");
		return -ENOTSUPP;
	}

	v = readq(csr_base + HSSI_CAPABILITY);
	qsfp_cnt = FIELD_GET(NUM_QSFP_INTERFACES, v);

	hssi = devm_kzalloc(dev, sizeof(*hssi) + qsfp_cnt * sizeof(void *),
			    GFP_KERNEL);
	if (!hssi)
		return -ENOMEM;

	dev_set_drvdata(&dfl_dev->dev, hssi);

	hssi->csr_base = csr_base;
	hssi->dev = dev;

	for (i = 0; i < qsfp_cnt; i++) {
		ret = hssi_create_qsfp(hssi, dfl_dev, i);
		if (ret)
			goto error_exit;
	}

	return 0;

error_exit:
	for (i = 0; i < hssi->qsfp_cnt; i++)
		hssi_destroy_qsfp(hssi, i);

	return ret;
}

static void dfl_hssi_remove(struct dfl_device *dfl_dev)
{
	struct dfl_hssi *hssi = dev_get_drvdata(&dfl_dev->dev);
	int i;

	for (i = 0; i < hssi->qsfp_cnt; i++)
		hssi_destroy_qsfp(hssi, i);
}

#define FME_FEATURE_ID_HSSI_ETH	0xa

static const struct dfl_device_id dfl_hssi_ids[] = {
	{ FME_ID, FME_FEATURE_ID_HSSI_ETH },
	{ }
};

static struct dfl_driver dfl_hssi_driver = {
	.drv = {
		.name = "intel-s10-hssi",
		.dev_groups = hssi_groups,
	},
	.id_table = dfl_hssi_ids,
	.probe = dfl_hssi_probe,
	.remove = dfl_hssi_remove,
};

module_dfl_driver(dfl_hssi_driver);

MODULE_DEVICE_TABLE(dfl, dfl_hssi_ids);
MODULE_DESCRIPTION("DFL HSSI driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
