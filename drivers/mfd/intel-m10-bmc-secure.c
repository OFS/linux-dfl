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
#include <linux/slab.h>
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

static int get_root_entry_hash(struct ifpga_sec_mgr *imgr, u32 exp_magic,
			       u32 prog_addr, u32 hash_addr, u8 **hash,
			       unsigned int *hash_size)
{
	struct m10bmc_sec *sec = imgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	u32 magic, sha_num_bytes;
	int ret;

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

	*hash = vmalloc(sizeof(u8) * sha_num_bytes);
	if (!*hash)
		return -ENOMEM;

	ret = m10bmc_raw_bulk_read(sec->m10bmc, hash_addr,
				   *hash, sha_num_bytes / stride);
	if (ret) {
		dev_err(sec->dev, "bulk_read of 0x%x failed %d",
			hash_addr, ret);
		vfree(*hash);
		return ret;
	}

	*hash_size = sha_num_bytes;
	return 0;
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

#define SYSFS_GET_REH(_name, _magic, _prog_addr, _hash_addr) \
	static int get_##_name##_root_entry_hash(struct ifpga_sec_mgr *imgr, \
						 u8 **hash, \
						 unsigned int *hash_size) \
	{ \
		return get_root_entry_hash(imgr, _magic, _prog_addr, \
					   _hash_addr, hash, hash_size); \
	}

SYSFS_GET_REH(bmc, BMC_PROG_MAGIC, BMC_PROG_ADDR, BMC_REH_ADDR)
SYSFS_GET_REH(sr, SR_PROG_MAGIC, SR_PROG_ADDR, SR_REH_ADDR)
SYSFS_GET_REH(pr, PR_PROG_MAGIC, PR_PROG_ADDR, PR_REH_ADDR)

#define FLASH_COUNT_SIZE 4096
#define USER_FLASH_COUNT 0x17ffb000

static int get_qspi_flash_count(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	unsigned int cnt, num_bits = FLASH_COUNT_SIZE * 8;
	u8 *flash_buf;
	int ret;

	flash_buf = kmalloc(FLASH_COUNT_SIZE, GFP_KERNEL);
	if (!flash_buf)
		return -ENOMEM;

	ret = m10bmc_raw_bulk_read(sec->m10bmc, USER_FLASH_COUNT, flash_buf,
				   FLASH_COUNT_SIZE / stride);
	if (ret) {
		dev_err(sec->dev, "%s failed to read %d\n", __func__, ret);
		goto exit_free;
	}

	cnt = num_bits - bitmap_weight((unsigned long *)flash_buf, num_bits);

exit_free:
	kfree(flash_buf);

	return ret ? : cnt;
}

#define CSK_BIT_LEN         128U
#define CSK_32ARRAY_SIZE    DIV_ROUND_UP(CSK_BIT_LEN, 32)

static int get_csk_vector(struct ifpga_sec_mgr *imgr, u32 addr,
			  unsigned long **csk_map, unsigned int *nbits)
{
	struct m10bmc_sec *sec = imgr->priv;
	u32 csk32[CSK_32ARRAY_SIZE];
	int i, ret;

	*csk_map = vmalloc(sizeof(unsigned long) * BITS_TO_LONGS(CSK_BIT_LEN));
	if (!*csk_map)
		return -ENOMEM;

	ret = m10bmc_raw_bulk_read(sec->m10bmc, addr, csk32, CSK_32ARRAY_SIZE);
	if (ret) {
		dev_err(sec->dev, "%s failed to read %d\n", __func__, ret);
		vfree(*csk_map);
		return ret;
	}

	for (i = 0; i < CSK_32ARRAY_SIZE; i++)
		csk32[i] = le32_to_cpu(csk32[i]);

	bitmap_from_arr32(*csk_map, csk32, CSK_BIT_LEN);
	bitmap_complement(*csk_map, *csk_map, CSK_BIT_LEN);

	*nbits = CSK_BIT_LEN;
	return 0;
}

#define SYSFS_GET_CSK_VEC(_name, _addr) \
	static int get_##_name##_canceled_csks(struct ifpga_sec_mgr *imgr, \
					unsigned long **csk_map, \
					unsigned int *nbits) \
	{ return get_csk_vector(imgr, _addr, csk_map, nbits); }

#define CSK_VEC_OFFSET 0x34

SYSFS_GET_CSK_VEC(bmc, BMC_PROG_ADDR + CSK_VEC_OFFSET)
SYSFS_GET_CSK_VEC(sr, SR_PROG_ADDR + CSK_VEC_OFFSET)
SYSFS_GET_CSK_VEC(pr, PR_PROG_ADDR + CSK_VEC_OFFSET)

static const struct ifpga_sec_mgr_ops m10bmc_iops = {
	.user_flash_count = get_qspi_flash_count,
	.bmc_root_entry_hash = get_bmc_root_entry_hash,
	.sr_root_entry_hash = get_sr_root_entry_hash,
	.pr_root_entry_hash = get_pr_root_entry_hash,
	.sr_canceled_csks = get_sr_canceled_csks,
	.bmc_canceled_csks = get_bmc_canceled_csks,
	.pr_canceled_csks = get_pr_canceled_csks,
};

static void ifpga_sec_mgr_uinit(struct m10bmc_sec *sec)
{
	ifpga_sec_mgr_unregister(sec->imgr);
}

static int ifpga_sec_mgr_init(struct m10bmc_sec *sec)
{
	int ret;

	sec->imgr = ifpga_sec_mgr_create(sec->dev, dev_name(sec->dev),
					 &m10bmc_iops, sec);
	if (!sec->imgr)
		return -ENOMEM;

	ret = ifpga_sec_mgr_register(sec->imgr);
	if (ret) {
		ifpga_sec_mgr_free(sec->imgr);
		sec->imgr = NULL;
	}
	return ret;
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
		.name = INTEL_M10BMC_SEC_DRV_NAME,
	},
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_ALIAS("platform:" INTEL_M10BMC_SEC_DRV_NAME);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC secure engine");
MODULE_LICENSE("GPL");
