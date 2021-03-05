// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Secure Update Driver
 *
 * Copyright (C) 2019-2021 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/fpga/fpga-image-load.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/platform_device.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	struct fpga_image_load *imgld;
};

/* Root Entry Hash (REH) support */
#define REH_SHA256_SIZE		32
#define REH_SHA384_SIZE		48
#define REH_MAGIC		GENMASK(15, 0)
#define REH_SHA_NUM_BYTES	GENMASK(31, 16)

static ssize_t
show_root_entry_hash(struct device *dev, u32 exp_magic,
		     u32 prog_addr, u32 reh_addr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	int sha_num_bytes, i, cnt, ret;
	u8 hash[REH_SHA384_SIZE];
	u32 magic;

	ret = m10bmc_raw_read(sec->m10bmc, prog_addr, &magic);
	if (ret)
		return ret;

	dev_dbg(dev, "%s magic 0x%08x\n", __func__, magic);

	if (FIELD_GET(REH_MAGIC, magic) != exp_magic)
		return sysfs_emit(buf, "hash not programmed\n");

	sha_num_bytes = FIELD_GET(REH_SHA_NUM_BYTES, magic) / 8;
	if (sha_num_bytes != REH_SHA256_SIZE &&
	    sha_num_bytes != REH_SHA384_SIZE)   {
		dev_err(sec->dev, "%s bad sha num bytes %d\n", __func__,
			sha_num_bytes);
		return -EINVAL;
	}

	WARN_ON(sha_num_bytes % stride);
	ret = regmap_bulk_read(sec->m10bmc->regmap, reh_addr,
			       hash, sha_num_bytes / stride);
	if (ret) {
		dev_err(dev, "failed to read root entry hash: %x cnt %x: %d\n",
			reh_addr, sha_num_bytes / stride, ret);
		return ret;
	}

	cnt = sprintf(buf, "0x");
	for (i = 0; i < sha_num_bytes; i++)
		cnt += sprintf(buf + cnt, "%02x", hash[i]);
	cnt += sprintf(buf + cnt, "\n");

	return cnt;
}

#define DEVICE_ATTR_SEC_REH_RO(_name, _magic, _prog_addr, _reh_addr) \
static ssize_t _name##_root_entry_hash_show(struct device *dev, \
					    struct device_attribute *attr, \
					    char *buf) \
{ return show_root_entry_hash(dev, _magic, _prog_addr, _reh_addr, buf); } \
static DEVICE_ATTR_RO(_name##_root_entry_hash)

DEVICE_ATTR_SEC_REH_RO(bmc, BMC_PROG_MAGIC, BMC_PROG_ADDR, BMC_REH_ADDR);
DEVICE_ATTR_SEC_REH_RO(sr, SR_PROG_MAGIC, SR_PROG_ADDR, SR_REH_ADDR);
DEVICE_ATTR_SEC_REH_RO(pr, PR_PROG_MAGIC, PR_PROG_ADDR, PR_REH_ADDR);

static struct attribute *m10bmc_security_attrs[] = {
	&dev_attr_bmc_root_entry_hash.attr,
	&dev_attr_sr_root_entry_hash.attr,
	&dev_attr_pr_root_entry_hash.attr,
	NULL,
};

static struct attribute_group m10bmc_security_attr_group = {
	.name = "security",
	.attrs = m10bmc_security_attrs,
};

static const struct attribute_group *m10bmc_sec_attr_groups[] = {
	&m10bmc_security_attr_group,
	NULL,
};

static const struct fpga_image_load_ops m10bmc_ops = { };

static int m10bmc_sec_probe(struct platform_device *pdev)
{
	struct fpga_image_load *imgld;
	struct m10bmc_sec *sec;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	dev_set_drvdata(&pdev->dev, sec);

	imgld = fpga_image_load_register(sec->dev, &m10bmc_ops, sec);
	if (IS_ERR(imgld)) {
		dev_err(sec->dev, "FPGA Image Load driver failed to start\n");
		return PTR_ERR(imgld);
	}

	sec->imgld = imgld;
	return 0;
}

static int m10bmc_sec_remove(struct platform_device *pdev)
{
	struct m10bmc_sec *sec = dev_get_drvdata(&pdev->dev);

	fpga_image_load_unregister(sec->imgld);
	return 0;
}

static struct platform_driver intel_m10bmc_sec_driver = {
	.probe = m10bmc_sec_probe,
	.remove = m10bmc_sec_remove,
	.driver = {
		.name = "n3000bmc-sec-update",
		.dev_groups = m10bmc_sec_attr_groups,
	},
};
module_platform_driver(intel_m10bmc_sec_driver);

MODULE_ALIAS("platform:n3000bmc-sec-update");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Secure Update");
MODULE_LICENSE("GPL v2");
