// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Security Engine Driver
 *
 * Copyright (C) 2019-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/device.h>
#include <linux/fpga/ifpga-sec-mgr.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/vmalloc.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	struct ifpga_sec_mgr *imgr;
};

/*
 * register access helper functions.
 *
 * m10bmc_raw_bulk_read - bulk_read max10 registers per addr
 */
static int m10bmc_raw_bulk_read(struct intel_m10bmc *m10bmc, unsigned int addr,
				void *val, size_t cnt)
{
	int ret;

	ret = regmap_bulk_read(m10bmc->regmap, addr, val, cnt);
	if (ret)
		dev_err(m10bmc->dev, "fail to read raw reg %x cnt %zx: %d\n",
			addr, cnt, ret);

	return ret;
}

#define SHA256_REH_SIZE		32
#define SHA384_REH_SIZE		48

static int get_reh_size(struct ifpga_sec_mgr *imgr,
			u32 exp_magic, u32 prog_addr)
{
	struct m10bmc_sec *sec = imgr->priv;
	int sha_num_bytes, ret;
	u32 magic;

	ret = m10bmc_raw_read(sec->m10bmc, prog_addr, &magic);
	if (ret)
		return ret;

	dev_dbg(sec->dev, "%s magic 0x%08x\n", __func__, magic);

	if ((magic & 0xffff) != exp_magic)
		return 0;

	sha_num_bytes = ((magic >> 16) & 0xffff) / 8;

	if (sha_num_bytes != SHA256_REH_SIZE &&
	    sha_num_bytes != SHA384_REH_SIZE)   {
		dev_err(sec->dev, "%s bad sha num bytes %d\n", __func__,
			sha_num_bytes);
		return -EINVAL;
	}

	return sha_num_bytes;
}

#define BMC_REH_ADDR 0x17ffc004
#define BMC_PROG_ADDR 0x17ffc000
#define BMC_PROG_MAGIC 0x5746

#define SR_REH_ADDR 0x17ffd004
#define SR_PROG_ADDR 0x17ffd000
#define SR_PROG_MAGIC 0x5253

#define PR_REH_ADDR 0x17ffe004
#define PR_PROG_ADDR 0x17ffe000
#define PR_PROG_MAGIC 0x5250

#define SYSFS_GET_REH_SIZE(_name, _exp_magic, _prog_addr) \
static int get_##_name##_reh_size(struct ifpga_sec_mgr *imgr) \
{ \
	return get_reh_size(imgr, _exp_magic, _prog_addr); \
}

SYSFS_GET_REH_SIZE(bmc, BMC_PROG_MAGIC, BMC_PROG_ADDR)
SYSFS_GET_REH_SIZE(sr, SR_PROG_MAGIC, SR_PROG_ADDR)
SYSFS_GET_REH_SIZE(pr, PR_PROG_MAGIC, PR_PROG_ADDR)

static int get_root_entry_hash(struct ifpga_sec_mgr *imgr,
			       u32 hash_addr, u8 *hash,
			       unsigned int size)
{
	struct m10bmc_sec *sec = imgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	int ret;

	ret = m10bmc_raw_bulk_read(sec->m10bmc, hash_addr,
				   hash, size / stride);
	if (ret)
		dev_err(sec->dev, "bulk_read of 0x%x failed %d",
			hash_addr, ret);

	return ret;
}

#define SYSFS_GET_REH(_name, _hash_addr) \
static int get_##_name##_root_entry_hash(struct ifpga_sec_mgr *imgr, \
					 u8 *hash, unsigned int size) \
{ \
	return get_root_entry_hash(imgr, _hash_addr, hash, size); \
}

SYSFS_GET_REH(bmc, BMC_REH_ADDR)
SYSFS_GET_REH(sr, SR_REH_ADDR)
SYSFS_GET_REH(pr, PR_REH_ADDR)

static const struct ifpga_sec_mgr_ops m10bmc_iops = {
	.bmc_root_entry_hash = get_bmc_root_entry_hash,
	.sr_root_entry_hash = get_sr_root_entry_hash,
	.pr_root_entry_hash = get_pr_root_entry_hash,
	.bmc_reh_size = get_bmc_reh_size,
	.sr_reh_size = get_sr_reh_size,
	.pr_reh_size = get_pr_reh_size,
};

static void ifpga_sec_mgr_uinit(struct m10bmc_sec *sec)
{
	ifpga_sec_mgr_unregister(sec->imgr);
}

static int ifpga_sec_mgr_init(struct m10bmc_sec *sec)
{
	struct ifpga_sec_mgr *imgr;

	imgr = ifpga_sec_mgr_register(sec->dev, "Max10 BMC Security Manager",
				      &m10bmc_iops, sec);
	if (IS_ERR(imgr))
		return PTR_ERR(imgr);

	sec->imgr = imgr;
	return 0;
}

static int m10bmc_secure_probe(struct platform_device *pdev)
{
	struct m10bmc_sec *sec;
	int ret;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	dev_set_drvdata(&pdev->dev, sec);

	ret = ifpga_sec_mgr_init(sec);
	if (ret)
		dev_err(&pdev->dev,
			"Security manager failed to start: %d\n", ret);

	return ret;
}

static int m10bmc_secure_remove(struct platform_device *pdev)
{
	struct m10bmc_sec *sec = dev_get_drvdata(&pdev->dev);

	ifpga_sec_mgr_uinit(sec);
	return 0;
}

static struct platform_driver intel_m10bmc_secure_driver = {
	.probe = m10bmc_secure_probe,
	.remove = m10bmc_secure_remove,
	.driver = {
		.name = "n3000bmc-secure",
	},
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_ALIAS("platform:n3000bmc-secure");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC secure engine");
MODULE_LICENSE("GPL v2");
