// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 BMC Retimer Interface Driver
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define N3000BMC_RETIMER_DEV_NAME "n3000bmc-retimer"

struct m10bmc_retimer {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	u32 ver_reg;
	u32 id;
};

static ssize_t tag_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct m10bmc_retimer *retimer = dev_get_drvdata(dev);

	return sysfs_emit(buf, "retimer_%c\n", 'A' + retimer->id);
}
static DEVICE_ATTR_RO(tag);

static ssize_t sbus_version_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct m10bmc_retimer *retimer = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(retimer->m10bmc, retimer->ver_reg, &val);
	if (ret)
		return ret;

	return sysfs_emit(buf, "0x%04x\n",
			  (u16)FIELD_GET(M10BMC_PKVL_SBUS_VER, val));
}
static DEVICE_ATTR_RO(sbus_version);

static ssize_t serdes_version_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct m10bmc_retimer *retimer = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(retimer->m10bmc, retimer->ver_reg, &val);
	if (ret)
		return ret;

	return sysfs_emit(buf, "0x%04x\n",
			  (u16)FIELD_GET(M10BMC_PKVL_SERDES_VER, val));
}
static DEVICE_ATTR_RO(serdes_version);

struct link_attr {
	struct device_attribute attr;
	u32 index;
};

#define to_link_attr(dev_attr) \
	container_of(dev_attr, struct link_attr, attr)

static ssize_t
link_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct m10bmc_retimer *retimer = dev_get_drvdata(dev);
	struct link_attr *lattr = to_link_attr(attr);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(retimer->m10bmc, M10BMC_PKVL_LSTATUS, &val);
	if (ret)
		return ret;

	return sysfs_emit(buf, "%u\n",
			  !!(val & BIT((retimer->id << 2) + lattr->index)));
}

#define link_status_attr(_index)					\
	static struct link_attr link_attr_status##_index =	\
		{ .attr = __ATTR(link_status##_index, 0444,	\
				 link_status_show, NULL),	\
		  .index = (_index) }

link_status_attr(0);
link_status_attr(1);
link_status_attr(2);
link_status_attr(3);

static struct attribute *m10bmc_retimer_attrs[] = {
	&dev_attr_tag.attr,
	&dev_attr_sbus_version.attr,
	&dev_attr_serdes_version.attr,
	&link_attr_status0.attr.attr,
	&link_attr_status1.attr.attr,
	&link_attr_status2.attr.attr,
	&link_attr_status3.attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(m10bmc_retimer);

static int intel_m10bmc_retimer_probe(struct platform_device *pdev)
{
	struct intel_m10bmc *m10bmc = dev_get_drvdata(pdev->dev.parent);
	struct m10bmc_retimer *retimer;
	struct resource *res;

	retimer = devm_kzalloc(&pdev->dev, sizeof(*retimer), GFP_KERNEL);
	if (!retimer)
		return -ENOMEM;

	res = platform_get_resource_byname(pdev, IORESOURCE_REG, "version");
	if (!res) {
		dev_err(&pdev->dev, "No REG resource for version\n");
		return -EINVAL;
	}

	/* find the id of the retimer via the addr of the version register */
	if (res->start == M10BMC_PKVL_A_VER) {
		retimer->id = 0;
	} else if (res->start == M10BMC_PKVL_B_VER) {
		retimer->id = 1;
	} else {
		dev_err(&pdev->dev, "version REG resource invalid\n");
		return -EINVAL;
	}

	retimer->ver_reg = res->start;
	retimer->dev = &pdev->dev;
	retimer->m10bmc = m10bmc;

	dev_set_drvdata(&pdev->dev, retimer);

	return 0;
}

static struct platform_driver intel_m10bmc_retimer_driver = {
	.probe = intel_m10bmc_retimer_probe,
	.driver = {
		.name = N3000BMC_RETIMER_DEV_NAME,
		.dev_groups = m10bmc_retimer_groups,
	},
};
module_platform_driver(intel_m10bmc_retimer_driver);

MODULE_ALIAS("platform:" N3000BMC_RETIMER_DEV_NAME);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX 10 BMC retimer driver");
MODULE_LICENSE("GPL");
