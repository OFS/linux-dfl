// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Secure Update Driver
 *
 * Copyright (C) 2019-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/fpga/fpga-sec-mgr.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
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

#define CSK_BIT_LEN		128U
#define CSK_32ARRAY_SIZE	DIV_ROUND_UP(CSK_BIT_LEN, 32)

static ssize_t
show_canceled_csk(struct device *dev, u32 addr, char *buf)
{
	unsigned int i, stride, size = CSK_32ARRAY_SIZE * sizeof(u32);
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	DECLARE_BITMAP(csk_map, CSK_BIT_LEN);
	__le32 csk_le32[CSK_32ARRAY_SIZE];
	u32 csk32[CSK_32ARRAY_SIZE];
	int ret;

	stride = regmap_get_reg_stride(sec->m10bmc->regmap);

	WARN_ON(size % stride);
	ret = regmap_bulk_read(sec->m10bmc->regmap, addr, csk_le32,
			       size / stride);
	if (ret) {
		dev_err(sec->dev, "failed to read CSK vector: %x cnt %x: %d\n",
			addr, size / stride, ret);
		return ret;
	}

	for (i = 0; i < CSK_32ARRAY_SIZE; i++)
		csk32[i] = le32_to_cpu(((csk_le32[i])));

	bitmap_from_arr32(csk_map, csk32, CSK_BIT_LEN);
	bitmap_complement(csk_map, csk_map, CSK_BIT_LEN);
	return bitmap_print_to_pagebuf(1, buf, csk_map, CSK_BIT_LEN);
}

#define DEVICE_ATTR_SEC_CSK_RO(_name, _addr) \
static ssize_t _name##_canceled_csks_show(struct device *dev, \
					  struct device_attribute *attr, \
					  char *buf) \
{ return show_canceled_csk(dev, _addr, buf); } \
static DEVICE_ATTR_RO(_name##_canceled_csks)

#define CSK_VEC_OFFSET 0x34

DEVICE_ATTR_SEC_CSK_RO(bmc, BMC_PROG_ADDR + CSK_VEC_OFFSET);
DEVICE_ATTR_SEC_CSK_RO(sr, SR_PROG_ADDR + CSK_VEC_OFFSET);
DEVICE_ATTR_SEC_CSK_RO(pr, PR_PROG_ADDR + CSK_VEC_OFFSET);

#define FLASH_COUNT_SIZE 4096	/* count stored as inverted bit vector */

static ssize_t flash_count_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	unsigned int stride, num_bits;
	u8 *flash_buf;
	int cnt, ret;

	stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	num_bits = FLASH_COUNT_SIZE * 8;

	flash_buf = kmalloc(FLASH_COUNT_SIZE, GFP_KERNEL);
	if (!flash_buf)
		return -ENOMEM;

	WARN_ON(FLASH_COUNT_SIZE % stride);
	ret = regmap_bulk_read(sec->m10bmc->regmap, STAGING_FLASH_COUNT,
			       flash_buf, FLASH_COUNT_SIZE / stride);
	if (ret) {
		dev_err(sec->dev,
			"failed to read flash count: %x cnt %x: %d\n",
			STAGING_FLASH_COUNT, FLASH_COUNT_SIZE / stride, ret);
		goto exit_free;
	}
	cnt = num_bits - bitmap_weight((unsigned long *)flash_buf, num_bits);

exit_free:
	kfree(flash_buf);

	return ret ? : sysfs_emit(buf, "%u\n", cnt);
}
static DEVICE_ATTR_RO(flash_count);

static struct attribute *m10bmc_security_attrs[] = {
	&dev_attr_flash_count.attr,
	&dev_attr_bmc_root_entry_hash.attr,
	&dev_attr_sr_root_entry_hash.attr,
	&dev_attr_pr_root_entry_hash.attr,
	&dev_attr_sr_canceled_csks.attr,
	&dev_attr_pr_canceled_csks.attr,
	&dev_attr_bmc_canceled_csks.attr,
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

static const struct fpga_sec_mgr_ops m10bmc_sops = { };

static int m10bmc_secure_probe(struct platform_device *pdev)
{
	struct fpga_sec_mgr *smgr;
	struct m10bmc_sec *sec;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	dev_set_drvdata(&pdev->dev, sec);

	smgr = devm_fpga_sec_mgr_create(sec->dev, "Max10 BMC Secure Update",
					&m10bmc_sops, sec);
	if (!smgr) {
		dev_err(sec->dev, "Security manager failed to start\n");
		return -ENOMEM;
	}

	return devm_fpga_sec_mgr_register(sec->dev, smgr);
}

static struct platform_driver intel_m10bmc_secure_driver = {
	.probe = m10bmc_secure_probe,
	.driver = {
		.name = "n3000bmc-secure",
		.dev_groups = m10bmc_sec_attr_groups,
	},
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_ALIAS("platform:n3000bmc-secure");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Secure Update");
MODULE_LICENSE("GPL v2");
