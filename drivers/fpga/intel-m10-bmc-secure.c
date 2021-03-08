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
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	enum fpga_sec_type type;
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

	ret = sec->m10bmc->ops.flash_read(sec->m10bmc, hash, reh_addr,
					   sha_num_bytes);
	if (ret) {
		dev_err(dev, "failed to read root entry hash\n");
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
	unsigned int i, size = CSK_32ARRAY_SIZE * sizeof(u32);
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	DECLARE_BITMAP(csk_map, CSK_BIT_LEN);
	__le32 csk_le32[CSK_32ARRAY_SIZE];
	u32 csk32[CSK_32ARRAY_SIZE];
	int ret;

	ret = sec->m10bmc->ops.flash_read(sec->m10bmc, csk_le32, addr, size);
	if (ret) {
		dev_err(sec->dev, "failed to read CSK vector\n");
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
	unsigned int num_bits;
	u8 *flash_buf;
	int cnt, ret;

	num_bits = FLASH_COUNT_SIZE * 8;

	flash_buf = kmalloc(FLASH_COUNT_SIZE, GFP_KERNEL);
	if (!flash_buf)
		return -ENOMEM;

	ret = sec->m10bmc->ops.flash_read(sec->m10bmc, flash_buf,
					   STAGING_FLASH_COUNT,
					   FLASH_COUNT_SIZE);
	if (ret) {
		dev_err(sec->dev, "failed to read flash count\n");
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

static void log_error_regs(struct m10bmc_sec *sec, u32 doorbell)
{
	u32 auth_result;

	dev_err(sec->dev, "RSU error status: 0x%08x\n", doorbell);

	if (!m10bmc_sys_read(sec->m10bmc, auth_result_reg(sec->m10bmc), &auth_result))
		dev_err(sec->dev, "RSU auth result: 0x%08x\n", auth_result);
}

static bool rsu_status_ok(u32 status)
{
	return (status == RSU_STAT_NORMAL ||
		status == RSU_STAT_NIOS_OK ||
		status == RSU_STAT_USER_OK ||
		status == RSU_STAT_FACTORY_OK);
}

static bool rsu_progress_done(u32 progress)
{
	return (progress == RSU_PROG_IDLE ||
		progress == RSU_PROG_RSU_DONE);
}

static bool rsu_progress_busy(u32 progress)
{
	return (progress == RSU_PROG_AUTHENTICATING ||
		progress == RSU_PROG_COPYING ||
		progress == RSU_PROG_UPDATE_CANCEL ||
		progress == RSU_PROG_PROGRAM_KEY_HASH);
}

static int
m10bmc_sec_status(struct m10bmc_sec *sec, u32 *status)
{
	u32 reg_offset, reg_value;
	int ret;

	reg_offset = (sec->m10bmc->type == M10_PMCI) ?
		auth_result_reg(sec->m10bmc) : doorbell_reg(sec->m10bmc);

	ret = m10bmc_sys_read(sec->m10bmc, reg_offset, &reg_value);
	if (ret)
		return ret;

	*status = rsu_stat(reg_value);

	return 0;
}

static int
m10bmc_sec_progress_status(struct m10bmc_sec *sec, u32 *doorbell,
			   u32 *progress, u32 *status)
{
	u32 auth_reg;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc,
			      doorbell_reg(sec->m10bmc),
			      doorbell);
	if (ret)
		return ret;

	*progress = rsu_prog(*doorbell);

	if (sec->m10bmc->type == M10_PMCI) {
		ret = m10bmc_sys_read(sec->m10bmc,
				      auth_result_reg(sec->m10bmc),
				      &auth_reg);
		if (ret)
			return ret;
		*status = rsu_stat(auth_reg);
	} else {
		*status = rsu_stat(*doorbell);
	}

	return 0;
}

static enum fpga_sec_err rsu_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	if (!rsu_progress_done(rsu_prog(doorbell))) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_BUSY;
	}

	return FPGA_SEC_ERR_NONE;
}

static inline bool rsu_start_done(u32 doorbell, u32 progress, u32 status)
{
	if (doorbell & DRBL_RSU_REQUEST)
		return false;

	if (status == RSU_STAT_ERASE_FAIL || status == RSU_STAT_WEAROUT)
		return true;

	if (!rsu_progress_done(progress))
		return true;

	return false;
}

static int rsu_poll_start_done(struct m10bmc_sec *sec, u32 *doorbell,
			       u32 *progress, u32 *status)
{
	unsigned long poll_timeout;
	int ret;

	poll_timeout = jiffies + msecs_to_jiffies(NIOS_HANDSHAKE_TIMEOUT_US);
	do {
		usleep_range(NIOS_HANDSHAKE_INTERVAL_US,
			     NIOS_HANDSHAKE_INTERVAL_US + 10);

		if (time_after(jiffies, poll_timeout))
			return -ETIMEDOUT;

		ret = m10bmc_sec_progress_status(sec, doorbell, progress, status);
		if (ret)
			return ret;

	} while (!rsu_start_done(*doorbell, *progress, *status));

	return 0;
}

static enum fpga_sec_err rsu_update_init(struct m10bmc_sec *sec)
{
	u32 doorbell, progress, status;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_RSU_REQUEST | DRBL_HOST_STATUS,
				     DRBL_RSU_REQUEST |
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_IDLE));
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	ret = rsu_poll_start_done(sec, &doorbell, &progress, &status);
	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	}

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

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	poll_timeout = jiffies + msecs_to_jiffies(RSU_PREP_TIMEOUT_MS);
	while (rsu_prog(doorbell) == RSU_PROG_PREPARE) {
		msleep(RSU_PREP_INTERVAL_MS);
		if (time_after(jiffies, poll_timeout))
			break;

		ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
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
	u32 doorbell, status;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_WRITE_DONE));
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       m10bmc_base(sec->m10bmc) + doorbell_reg(sec->m10bmc),
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

	ret = m10bmc_sec_status(sec, &status);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	if (!rsu_status_ok(status)) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	return FPGA_SEC_ERR_NONE;
}

static int rsu_check_complete(struct m10bmc_sec *sec, u32 *doorbell)
{
	u32 progress, status;

	if (m10bmc_sec_progress_status(sec, doorbell, &progress, &status))
		return -EIO;

	if (!rsu_status_ok(status))
		return -EINVAL;

	if (rsu_progress_done(progress))
		return 0;

	if (rsu_progress_busy(progress))
		return -EAGAIN;

	return -EINVAL;
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
	if (ret == FPGA_SEC_ERR_NONE)
		goto fw_state_exit;

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

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	ret = regmap_bulk_write(sec->m10bmc->regmap,
				M10BMC_STAGING_BASE + offset,
				(void *)smgr->data + offset,
				(size + stride - 1) / stride);

	return ret ? FPGA_SEC_ERR_RW_ERROR : FPGA_SEC_ERR_NONE;
}

static enum fpga_sec_err
pmci_sec_write_blk(struct fpga_sec_mgr *smgr, u32 offset, u32 size)
{
	struct m10bmc_sec *sec = smgr->priv;
	struct intel_m10bmc *m10bmc = sec->m10bmc;
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret) {
		return FPGA_SEC_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FPGA_SEC_ERR_HW_ERROR;
	}

	ret = m10bmc->flash_ops->write_blk(m10bmc,
					   (void *)smgr->data + offset, size);

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

	poll_timeout = jiffies + msecs_to_jiffies(RSU_COMPLETE_TIMEOUT_MS);
	do {
		msleep(RSU_COMPLETE_INTERVAL_MS);
		ret = rsu_check_complete(sec, &doorbell);
		if (smgr->driver_unload) {
			result = FPGA_SEC_ERR_CANCELED;
			goto fw_state_exit;
		}
	} while (ret == -EAGAIN && !time_after(jiffies, poll_timeout));

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

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FPGA_SEC_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_READY)
		return FPGA_SEC_ERR_BUSY;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_ABORT_RSU));

	return ret ? FPGA_SEC_ERR_RW_ERROR : FPGA_SEC_ERR_NONE;
}

#define HW_ERRINFO_POISON	GENMASK(31, 0)
static u64 m10bmc_sec_hw_errinfo(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	u32 auth_result = HW_ERRINFO_POISON;
	u32 doorbell = HW_ERRINFO_POISON;

	switch (smgr->err_code) {
	case FPGA_SEC_ERR_HW_ERROR:
	case FPGA_SEC_ERR_TIMEOUT:
	case FPGA_SEC_ERR_BUSY:
	case FPGA_SEC_ERR_WEAROUT:
		m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
		m10bmc_sys_read(sec->m10bmc, auth_result_reg(sec->m10bmc), &auth_result);

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

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return ret;

	if (doorbell & DRBL_REBOOT_DISABLED)
		return -EBUSY;

	return m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
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

static int retimer_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return -EIO;

	if (rsu_prog(doorbell) != RSU_PROG_IDLE &&
	    rsu_prog(doorbell) != RSU_PROG_RSU_DONE &&
	    rsu_prog(doorbell) != RSU_PROG_PKVL_PROM_DONE) {
		log_error_regs(sec, doorbell);
		return -EBUSY;
	}

	return 0;
}

static int trigger_retimer_eeprom_load(struct m10bmc_sec *sec)
{
	struct intel_m10bmc *m10bmc = sec->m10bmc;
	unsigned int val;
	int ret;

	ret = m10bmc_sys_update_bits(m10bmc, doorbell_reg(m10bmc),
				     DRBL_PKVL_EEPROM_LOAD_SEC,
				     DRBL_PKVL_EEPROM_LOAD_SEC);
	if (ret)
		return ret;

	/*
	 * If the current NIOS FW supports this retimer update feature, then
	 * it will clear the same PKVL_EEPROM_LOAD bit in 2 seconds. Otherwise
	 * the driver needs to clear the PKVL_EEPROM_LOAD bit manually and
	 * return an error code.
	 */
	ret = regmap_read_poll_timeout(m10bmc->regmap,
				       m10bmc_base(m10bmc) + doorbell_reg(m10bmc),
				       val,
				       (!(val & DRBL_PKVL_EEPROM_LOAD_SEC)),
				       M10BMC_PKVL_LOAD_INTERVAL_US,
				       M10BMC_PKVL_LOAD_TIMEOUT_US);
	if (ret == -ETIMEDOUT) {
		dev_err(sec->dev, "%s PKVL_EEPROM_LOAD clear timedout\n",
			__func__);
		m10bmc_sys_update_bits(m10bmc, doorbell_reg(m10bmc),
				       DRBL_PKVL_EEPROM_LOAD_SEC, 0);
		ret = -ENODEV;
	} else if (ret) {
		dev_err(sec->dev, "%s poll EEPROM_LOAD error %d\n",
			__func__, ret);
	}

	return ret;
}

static int poll_retimer_eeprom_load_done(struct m10bmc_sec *sec)
{
	struct intel_m10bmc *m10bmc = sec->m10bmc;
	unsigned int doorbell;
	int ret;

	/*
	 * RSU_STAT_PKVL_REJECT indicates that the current image is
	 * already programmed. RSU_PROG_PKVL_PROM_DONE that the firmware
	 * update process has finished, but does not necessarily indicate
	 * a successful update.
	 */
	ret = regmap_read_poll_timeout(m10bmc->regmap,
				       m10bmc_base(m10bmc) + doorbell_reg(m10bmc),
				       doorbell,
				       ((rsu_prog(doorbell) ==
					 RSU_PROG_PKVL_PROM_DONE) ||
					(rsu_stat(doorbell) ==
					 RSU_STAT_PKVL_REJECT)),
				       M10BMC_PKVL_PRELOAD_INTERVAL_US,
				       M10BMC_PKVL_PRELOAD_TIMEOUT_US);
	if (ret) {
		if (ret == -ETIMEDOUT)
			dev_err(sec->dev,
				"%s Doorbell check timedout: 0x%08x\n",
				__func__, doorbell);
		else
			dev_err(sec->dev, "%s poll Doorbell error\n",
				__func__);
		return ret;
	}

	if (rsu_stat(doorbell) == RSU_STAT_PKVL_REJECT) {
		dev_err(sec->dev, "%s duplicate image rejected\n", __func__);
		return -ECANCELED;
	}

	return 0;
}

static int poll_retimer_preload_done(struct m10bmc_sec *sec)
{
	struct intel_m10bmc *m10bmc = sec->m10bmc;
	unsigned int val;
	int ret;

	/*
	 * Wait for the updated firmware to be loaded by the PKVL device
	 * and confirm that the updated firmware is operational
	 */
	ret = regmap_read_poll_timeout(m10bmc->regmap,
				       m10bmc_base(m10bmc) + M10BMC_PKVL_POLL_CTRL, val,
				       ((val & M10BMC_PKVL_PRELOAD) == M10BMC_PKVL_PRELOAD),
				       M10BMC_PKVL_PRELOAD_INTERVAL_US,
				       M10BMC_PKVL_PRELOAD_TIMEOUT_US);
	if (ret) {
		dev_err(sec->dev, "%s poll M10BMC_PKVL_PRELOAD error %d\n",
			__func__, ret);
		return ret;
	}

	if ((val & M10BMC_PKVL_UPG_STATUS_MASK) != M10BMC_PKVL_UPG_STATUS_GOOD) {
		dev_err(sec->dev, "%s error detected during upgrade\n",
			__func__);
		return -EIO;
	}

	return 0;
}

static int m10bmc_sec_retimer_eeprom_load(struct fpga_sec_mgr *smgr)
{
	struct m10bmc_sec *sec = smgr->priv;
	int ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return -EBUSY;

	ret = retimer_check_idle(sec);
	if (ret)
		goto fw_state_exit;

	ret = trigger_retimer_eeprom_load(sec);
	if (ret)
		goto fw_state_exit;

	ret = poll_retimer_eeprom_load_done(sec);
	if (ret)
		goto fw_state_exit;

	ret = poll_retimer_preload_done(sec);

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return ret;
}

static struct image_load n3000_image_load_hndlrs[] = {
	{
		.name = "bmc_factory",
		.load_image = m10bmc_sec_bmc_image_load_1,
	},
	{
		.name = "bmc_user",
		.load_image = m10bmc_sec_bmc_image_load_0,
	},
	{
		.name = "retimer_fw",
		.load_image = m10bmc_sec_retimer_eeprom_load,
	},
	{}
};

static struct image_load d5005_image_load_hndlrs[] = {
	{
		.name = "bmc_factory",
		.load_image = m10bmc_sec_bmc_image_load_0,
	},
	{
		.name = "bmc_user",
		.load_image = m10bmc_sec_bmc_image_load_1,
	},
	{}
};

static struct fpga_sec_mgr_ops *
m10bmc_sops_create(struct device *dev, enum fpga_sec_type type)
{
	struct fpga_sec_mgr_ops *sops;

	sops = devm_kzalloc(dev, sizeof(*sops), GFP_KERNEL);
	if (!sops)
		return NULL;

	sops->prepare = m10bmc_sec_prepare;
	sops->write_blk = m10bmc_sec_write_blk;
	sops->poll_complete = m10bmc_sec_poll_complete;
	sops->cancel = m10bmc_sec_cancel;
	sops->get_hw_errinfo = m10bmc_sec_hw_errinfo;

	if (type == PMCI_SEC)
		sops->write_blk = pmci_sec_write_blk;
	else
		sops->write_blk = m10bmc_sec_write_blk;

	if (type == N3000BMC_SEC)
		sops->image_load = n3000_image_load_hndlrs;
	else if (type == D5005BMC_SEC)
		sops->image_load = d5005_image_load_hndlrs;

	return sops;
}

static int m10bmc_secure_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	enum fpga_sec_type type = (enum fpga_sec_type)id->driver_data;
	struct fpga_sec_mgr_ops *sops;
	struct fpga_sec_mgr *smgr;
	struct m10bmc_sec *sec;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sops = m10bmc_sops_create(&pdev->dev, type);
	if (!sops)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	sec->type = type;
	dev_set_drvdata(&pdev->dev, sec);

	if (type == PMCI_SEC && !sec->m10bmc->flash_ops) {
		dev_err(sec->dev, "No flash-ops provided for security manager\n");
		return -EINVAL;
	}

	smgr = devm_fpga_sec_mgr_create(sec->dev, "Max10 BMC Secure Update",
					sops, sec);
	if (!smgr) {
		dev_err(sec->dev, "Security manager failed to start\n");
		return -ENOMEM;
	}

	return devm_fpga_sec_mgr_register(sec->dev, smgr);
}

static const struct platform_device_id intel_m10bmc_secure_ids[] = {
	{
		.name = "n3000bmc-secure",
		.driver_data = (unsigned long)N3000BMC_SEC,
	},
	{
		.name = "d5005bmc-secure",
		.driver_data = (unsigned long)D5005BMC_SEC,
	},
	{
		.name = "intel-pmci-secure",
		.driver_data = (unsigned long)PMCI_SEC,
	},
	{ }
};

static struct platform_driver intel_m10bmc_secure_driver = {
	.probe = m10bmc_secure_probe,
	.driver = {
		.name = "intel-m10bmc-secure",
		.dev_groups = m10bmc_sec_attr_groups,
	},
	.id_table = intel_m10bmc_secure_ids,
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_DEVICE_TABLE(platform, intel_m10bmc_secure_ids);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Secure Update");
MODULE_LICENSE("GPL v2");
