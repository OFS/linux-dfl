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
#include <linux/vmalloc.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
};

/* Root Entry Hash (REH) support */
#define REH_SHA256_SIZE		32
#define REH_SHA384_SIZE		48
#define REH_MAGIC		GENMASK(15, 0)
#define REH_SHA_NUM_BYTES	GENMASK(31, 16)

static int m10bmc_reh_size(struct fpga_sec_mgr *smgr,
			   u32 exp_magic, u32 prog_addr)
{
	struct m10bmc_sec *sec = smgr->priv;
	int sha_num_bytes, ret;
	u32 magic;

	ret = m10bmc_raw_read(sec->m10bmc, prog_addr, &magic);
	if (ret)
		return ret;

	dev_dbg(sec->dev, "%s magic 0x%08x\n", __func__, magic);

	/*
	 * If no magic number, then no Root Entry Hash (REH) is programmed,
	 * so the REH size is zero.
	 */
	if (FIELD_GET(REH_MAGIC, magic) != exp_magic)
		return 0;

	sha_num_bytes = FIELD_GET(REH_SHA_NUM_BYTES, magic) / 8;
	if (sha_num_bytes != REH_SHA256_SIZE &&
	    sha_num_bytes != REH_SHA384_SIZE)   {
		dev_err(sec->dev, "%s bad sha num bytes %d\n", __func__,
			sha_num_bytes);
		return -EINVAL;
	}

	return sha_num_bytes;
}

static int m10bmc_bmc_reh_size(struct fpga_sec_mgr *smgr)
{
	return m10bmc_reh_size(smgr, BMC_PROG_MAGIC, BMC_PROG_ADDR);
}

static int m10bmc_sr_reh_size(struct fpga_sec_mgr *smgr)
{
	return m10bmc_reh_size(smgr, SR_PROG_MAGIC, SR_PROG_ADDR);
}

static int m10bmc_pr_reh_size(struct fpga_sec_mgr *smgr)
{
	return m10bmc_reh_size(smgr, PR_PROG_MAGIC, PR_PROG_ADDR);
}

static int m10bmc_reh(struct fpga_sec_mgr *smgr, u32 hash_addr,
		      u8 *hash, unsigned int size)
{
	struct m10bmc_sec *sec = smgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	int ret;

	ret = regmap_bulk_read(sec->m10bmc->regmap, hash_addr,
			       hash, size / stride);
	if (ret)
		dev_err(sec->m10bmc->dev,
			"failed to read root entry hash: %x cnt %x: %d\n",
			hash_addr, size / stride, ret);

	return ret;
}

static int m10bmc_bmc_reh(struct fpga_sec_mgr *smgr, u8 *hash,
			  unsigned int size)
{
	return m10bmc_reh(smgr, BMC_REH_ADDR, hash, size);
}

static int m10bmc_sr_reh(struct fpga_sec_mgr *smgr, u8 *hash,
			 unsigned int size)
{
	return m10bmc_reh(smgr, SR_REH_ADDR, hash, size);
}

static int m10bmc_pr_reh(struct fpga_sec_mgr *smgr, u8 *hash,
			 unsigned int size)
{
	return m10bmc_reh(smgr, PR_REH_ADDR, hash, size);
}

#define FLASH_COUNT_SIZE 4096	/* count stored in inverted bit vector */

static int m10bmc_user_flash_count(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	unsigned int num_bits = FLASH_COUNT_SIZE * 8;
	u8 *flash_buf;
	int ret;

	flash_buf = kmalloc(FLASH_COUNT_SIZE, GFP_KERNEL);
	if (!flash_buf)
		return -ENOMEM;

	ret = regmap_bulk_read(sec->m10bmc->regmap, USER_FLASH_COUNT,
			       flash_buf, FLASH_COUNT_SIZE / stride);
	if (ret) {
		dev_err(sec->dev,
			"failed to read flash count: %x cnt %x: %d\n",
			USER_FLASH_COUNT, FLASH_COUNT_SIZE / stride, ret);
		goto exit_free;
	}

	ret = num_bits - bitmap_weight((unsigned long *)flash_buf, num_bits);

exit_free:
	kfree(flash_buf);

	return ret;
}

#define CSK_BIT_LEN			128U
#define CSK_32ARRAY_SIZE(_nbits)	DIV_ROUND_UP(_nbits, 32)

static int m10bmc_csk_cancel_nbits(struct fpga_sec_mgr *smgr)
{
	return (int)CSK_BIT_LEN;
}

static int m10bmc_csk_vector(struct fpga_sec_mgr *smgr, u32 addr,
			     unsigned long *csk_map, unsigned int nbits)
{
	unsigned int i, size, arr_size = CSK_32ARRAY_SIZE(nbits);
	struct m10bmc_sec *sec = smgr->priv;
	unsigned int stride;
	__le32 *csk_le32;
	u32 *csk32;
	int ret;

	stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	size = arr_size * sizeof(u32);

	csk32 = vmalloc(size);
	if (!csk32)
		return -ENOMEM;

	csk_le32 = vmalloc(size);
	if (!csk_le32) {
		vfree(csk32);
		return -ENOMEM;
	}

	ret = regmap_bulk_read(sec->m10bmc->regmap, addr, csk_le32, size / stride);
	if (ret) {
		dev_err(sec->dev, "failed to read CSK vector: %x cnt %x: %d\n",
			addr, size / stride, ret);
		goto vfree_exit;
	}

	for (i = 0; i < arr_size; i++)
		csk32[i] = le32_to_cpu(((csk_le32[i])));

	bitmap_from_arr32(csk_map, csk32, nbits);
	bitmap_complement(csk_map, csk_map, nbits);

vfree_exit:
	vfree(csk_le32);
	vfree(csk32);
	return ret;
}

#define CSK_VEC_OFFSET 0x34

static int m10bmc_bmc_canceled_csks(struct fpga_sec_mgr *smgr,
				    unsigned long *csk_map,
				    unsigned int nbits)
{
	return m10bmc_csk_vector(smgr, BMC_PROG_ADDR + CSK_VEC_OFFSET,
				 csk_map, nbits);
}

static int m10bmc_sr_canceled_csks(struct fpga_sec_mgr *smgr,
				   unsigned long *csk_map,
				   unsigned int nbits)
{
	return m10bmc_csk_vector(smgr, SR_PROG_ADDR + CSK_VEC_OFFSET,
				 csk_map, nbits);
}

static int m10bmc_pr_canceled_csks(struct fpga_sec_mgr *smgr,
				   unsigned long *csk_map,
				   unsigned int nbits)
{
	return m10bmc_csk_vector(smgr, PR_PROG_ADDR + CSK_VEC_OFFSET,
				 csk_map, nbits);
}

static void log_error_regs(struct m10bmc_sec *sec, u32 doorbell)
{
	u32 auth_result;

	dev_err(sec->dev, "RSU error status: 0x%08x\n", doorbell);

	if (!m10bmc_sys_read(sec->m10bmc, M10BMC_AUTH_RESULT, &auth_result))
		dev_err(sec->dev, "RSU auth result: 0x%08x\n", auth_result);
}

static enum fpga_sec_err rsu_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_IDLE &&
	    rsu_prog(doorbell) != RSU_PROG_RSU_DONE) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_BUSY;
	}

	return FPGA_SEC_ERR_NONE;
}

static inline bool rsu_start_done(u32 doorbell)
{
	u32 status, progress;

	if (doorbell & DRBL_RSU_REQUEST)
		return false;

	status = rsu_stat(doorbell);
	if (status == RSU_STAT_ERASE_FAIL || status == RSU_STAT_WEAROUT)
		return true;

	progress = rsu_prog(doorbell);
	if (progress != RSU_PROG_IDLE && progress != RSU_PROG_RSU_DONE)
		return true;

	return false;
}

static enum fpga_sec_err rsu_update_init(struct m10bmc_sec *sec)
{
	u32 doorbell, status;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     DRBL_RSU_REQUEST | DRBL_HOST_STATUS,
				     DRBL_RSU_REQUEST |
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_IDLE));
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       doorbell,
				       rsu_start_done(doorbell),
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	}

	status = rsu_stat(doorbell);
	if (status == RSU_STAT_WEAROUT) {
		dev_warn(sec->dev, "Excessive flash update count detected\n");
		return FPGA_SEC_ERR_WEAROUT;
	} else if (status == RSU_STAT_ERASE_FAIL) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	return FPGA_SEC_ERR_NONE;
}

static enum fpga_sec_err rsu_prog_ready(struct m10bmc_sec *sec)
{
	unsigned long poll_timeout;
	u32 doorbell, progress;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	poll_timeout = jiffies + msecs_to_jiffies(RSU_PREP_TIMEOUT_MS);
	while (rsu_prog(doorbell) == RSU_PROG_PREPARE) {
		msleep(RSU_PREP_INTERVAL_MS);
		if (time_after(jiffies, poll_timeout))
			break;

		ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
		if (ret)
			return FPGA_SEC_ERR_RW_ERROR;
	}

	progress = rsu_prog(doorbell);
	if (progress == RSU_PROG_PREPARE) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_TIMEOUT;
	} else if (progress != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	return FPGA_SEC_ERR_NONE;
}

static enum fpga_sec_err rsu_send_data(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_WRITE_DONE));
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       doorbell,
				       rsu_prog(doorbell) != RSU_PROG_READY,
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	}

	switch (rsu_stat(doorbell)) {
	case RSU_STAT_NORMAL:
	case RSU_STAT_NIOS_OK:
	case RSU_STAT_USER_OK:
	case RSU_STAT_FACTORY_OK:
		break;
	default:
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	return FPGA_SEC_ERR_NONE;
}

static int rsu_check_complete(struct m10bmc_sec *sec, u32 *doorbell)
{
	if (m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, doorbell))
		return -EIO;

	switch (rsu_stat(*doorbell)) {
	case RSU_STAT_NORMAL:
	case RSU_STAT_NIOS_OK:
	case RSU_STAT_USER_OK:
	case RSU_STAT_FACTORY_OK:
	case RSU_STAT_WEAROUT:
		break;
	default:
		return -EINVAL;
	}

	switch (rsu_prog(*doorbell)) {
	case RSU_PROG_IDLE:
	case RSU_PROG_RSU_DONE:
		return 0;
	case RSU_PROG_AUTHENTICATING:
	case RSU_PROG_COPYING:
	case RSU_PROG_UPDATE_CANCEL:
	case RSU_PROG_PROGRAM_KEY_HASH:
		return -EAGAIN;
	default:
		return -EINVAL;
	}
}

static enum fpga_sec_err m10bmc_sec_prepare(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	enum fpga_sec_err ret;

	if (smgr->remaining_size > M10BMC_STAGING_SIZE)
		return FPGA_SEC_ERR_INVALID_SIZE;

	ret = rsu_check_idle(sec);
	if (ret != FPGA_SEC_ERR_NONE)
		return ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return FPGA_SEC_ERR_BUSY;

	ret = rsu_update_init(sec);
	if (ret != FPGA_SEC_ERR_NONE)
		goto fw_state_exit;

	ret = rsu_prog_ready(sec);

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return ret;
}

static enum fpga_sec_err
m10bmc_sec_write_blk(struct fpga_sec_mgr *smgr, u32 offset, u32 size)
{
	struct m10bmc_sec *sec = smgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	ret = regmap_bulk_write(sec->m10bmc->regmap,
				M10BMC_STAGING_BASE + offset,
				(void *)smgr->data + offset, size / stride);

	return ret ? FPGA_SEC_ERR_RW_ERROR : FPGA_SEC_ERR_NONE;
}

/*
 * m10bmc_sec_poll_complete() is called after handing things off to
 * the BMC firmware. Depending on the type of update, it could be
 * 30+ minutes before the BMC firmware completes the update. The
 * smgr->driver_unload check allows the driver to be unloaded,
 * but the BMC firmware will continue the update and no further
 * secure updates can be started for this device until the update
 * is complete.
 */
static enum fpga_sec_err m10bmc_sec_poll_complete(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	unsigned long poll_timeout;
	enum fpga_sec_err result;
	u32 doorbell;
	int ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return FPGA_SEC_ERR_BUSY;

	result = rsu_send_data(sec);
	if (result != FPGA_SEC_ERR_NONE)
		goto fw_state_exit;

	ret = rsu_check_complete(sec, &doorbell);
	poll_timeout = jiffies + msecs_to_jiffies(RSU_COMPLETE_TIMEOUT_MS);

	while (ret == -EAGAIN && !time_after(jiffies, poll_timeout)) {
		msleep(RSU_COMPLETE_INTERVAL_MS);
		ret = rsu_check_complete(sec, &doorbell);
		if (smgr->driver_unload) {
			result = FPGA_SEC_ERR_CANCELED;
			goto fw_state_exit;
		}
	}

	if (ret == -EAGAIN) {
		log_error_regs(sec, doorbell);
		result = FPGA_SEC_ERR_TIMEOUT;
	} else if (ret == -EIO) {
		result = FPGA_SEC_ERR_RW_ERROR;
	} else if (ret) {
		log_error_regs(sec, doorbell);
		result = FPGA_SEC_ERR_HW_ERROR;
	}

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return result;
}

static enum fpga_sec_err m10bmc_sec_cancel(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_READY)
		return FPGA_SEC_ERR_BUSY;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_ABORT_RSU));

	return ret ? FPGA_SEC_ERR_RW_ERROR : FPGA_SEC_ERR_NONE;
}

#define HW_ERRINFO_POISON	GENMASK(31, 0)
static u64 m10bmc_sec_hw_errinfo(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	u32 doorbell, auth_result;

	switch (smgr->err_code) {
	case FPGA_SEC_ERR_HW_ERROR:
	case FPGA_SEC_ERR_TIMEOUT:
	case FPGA_SEC_ERR_BUSY:
	case FPGA_SEC_ERR_WEAROUT:
		if (m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell))
			doorbell = HW_ERRINFO_POISON;

		if (m10bmc_sys_read(sec->m10bmc, M10BMC_AUTH_RESULT,
				    &auth_result))
			auth_result = HW_ERRINFO_POISON;

		return (u64)doorbell << 32 | (u64)auth_result;
	default:
		return 0;
	}
}

static int m10bmc_sec_bmc_image_load(struct fpga_sec_mgr *smgr,
				     unsigned int val)
{
	struct m10bmc_sec *sec = smgr->priv;
	u32 doorbell;
	int ret;

	if (val > 1) {
		dev_err(sec->dev, "%s invalid reload val = %d\n",
			__func__, val);
		return -EINVAL;
	}

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return ret;

	if (doorbell & DRBL_REBOOT_DISABLED)
		return -EBUSY;

	return m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     DRBL_CONFIG_SEL | DRBL_REBOOT_REQ,
				     FIELD_PREP(DRBL_CONFIG_SEL, val) |
				     DRBL_REBOOT_REQ);
}

static int m10bmc_sec_bmc_image_load_0(struct fpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 0);
}

static int m10bmc_sec_bmc_image_load_1(struct fpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 1);
}

static struct image_load n3000_image_load_hndlrs[] = {
	{
		.name = "bmc_user",
		.load_image = m10bmc_sec_bmc_image_load_0,
	},
	{
		.name = "bmc_factory",
		.load_image = m10bmc_sec_bmc_image_load_1,
	},
	{}
};

static struct fpga_sec_mgr_ops *
m10bmc_sops_create(struct device *dev)
{
	struct fpga_sec_mgr_ops *sops;

	sops = devm_kzalloc(dev, sizeof(*sops), GFP_KERNEL);
	if (!sops)
		return NULL;

	sops->user_flash_count = m10bmc_user_flash_count;
	sops->bmc_root_entry_hash = m10bmc_bmc_reh;
	sops->sr_root_entry_hash = m10bmc_sr_reh;
	sops->pr_root_entry_hash = m10bmc_pr_reh;
	sops->bmc_canceled_csks = m10bmc_bmc_canceled_csks;
	sops->sr_canceled_csks = m10bmc_sr_canceled_csks;
	sops->pr_canceled_csks = m10bmc_pr_canceled_csks;
	sops->bmc_reh_size = m10bmc_bmc_reh_size;
	sops->sr_reh_size = m10bmc_sr_reh_size;
	sops->pr_reh_size = m10bmc_pr_reh_size;
	sops->bmc_canceled_csk_nbits = m10bmc_csk_cancel_nbits;
	sops->sr_canceled_csk_nbits = m10bmc_csk_cancel_nbits;
	sops->pr_canceled_csk_nbits = m10bmc_csk_cancel_nbits;
	sops->prepare = m10bmc_sec_prepare;
	sops->write_blk = m10bmc_sec_write_blk;
	sops->poll_complete = m10bmc_sec_poll_complete;
	sops->cancel = m10bmc_sec_cancel;
	sops->get_hw_errinfo = m10bmc_sec_hw_errinfo;
	sops->image_load = n3000_image_load_hndlrs;

	return sops;
}

static int m10bmc_secure_probe(struct platform_device *pdev)
{
	struct fpga_sec_mgr_ops *sops;
	struct fpga_sec_mgr *smgr;
	struct m10bmc_sec *sec;
	int ret;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sops = m10bmc_sops_create(&pdev->dev);
	if (!sops)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	dev_set_drvdata(&pdev->dev, sec);

	smgr = devm_fpga_sec_mgr_create(sec->dev, "Max10 BMC Secure Update",
					sops, sec);
	if (!smgr) {
		dev_err(sec->dev,
			"Security manager failed to start: %d\n", ret);
		return -ENOMEM;
	}

	return devm_fpga_sec_mgr_register(sec->dev, smgr);
}

static struct platform_driver intel_m10bmc_secure_driver = {
	.probe = m10bmc_secure_probe,
	.driver = {
		.name = "n3000bmc-secure",
	},
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_ALIAS("platform:n3000bmc-secure");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Secure Update");
MODULE_LICENSE("GPL v2");
