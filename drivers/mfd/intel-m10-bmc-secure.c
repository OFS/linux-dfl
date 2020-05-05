// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Security Engine Driver
 *
 * Copyright (C) 2019-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/fpga/ifpga-sec-mgr.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	struct ifpga_sec_mgr *imgr;
};

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

#define CSK_BIT_LEN			128U
#define CSK_32ARRAY_SIZE(_nbits)	DIV_ROUND_UP(_nbits, 32)

#define SYSFS_GET_CSK_CANCEL_NBITS(_name) \
static int get_##_name##_csk_cancel_nbits(struct ifpga_sec_mgr *imgr) \
{ \
	return (int)CSK_BIT_LEN; \
}

SYSFS_GET_CSK_CANCEL_NBITS(bmc)
SYSFS_GET_CSK_CANCEL_NBITS(sr)
SYSFS_GET_CSK_CANCEL_NBITS(pr)

static int get_csk_vector(struct ifpga_sec_mgr *imgr, u32 addr,
			  unsigned long *csk_map, unsigned int nbits)
{
	unsigned int i, arr_size = CSK_32ARRAY_SIZE(nbits);
	struct m10bmc_sec *sec = imgr->priv;
	u32 *csk32;
	int ret;

	csk32 = vmalloc(arr_size);
	if (!csk32)
		return -ENOMEM;

	ret = m10bmc_raw_bulk_read(sec->m10bmc, addr, csk32, arr_size);
	if (ret) {
		dev_err(sec->dev, "%s failed to read %d\n", __func__, ret);
		goto vfree_exit;
	}

	for (i = 0; i < arr_size; i++)
		csk32[i] = le32_to_cpu(csk32[i]);

	bitmap_from_arr32(csk_map, csk32, nbits);
	bitmap_complement(csk_map, csk_map, nbits);

vfree_exit:
	vfree(csk32);
	return ret;
}

#define SYSFS_GET_CSK_VEC(_name, _addr) \
static int get_##_name##_canceled_csks(struct ifpga_sec_mgr *imgr, \
				       unsigned long *csk_map, \
				       unsigned int nbits) \
{ return get_csk_vector(imgr, _addr, csk_map, nbits); }

#define CSK_VEC_OFFSET 0x34

SYSFS_GET_CSK_VEC(bmc, BMC_PROG_ADDR + CSK_VEC_OFFSET)
SYSFS_GET_CSK_VEC(sr, SR_PROG_ADDR + CSK_VEC_OFFSET)
SYSFS_GET_CSK_VEC(pr, PR_PROG_ADDR + CSK_VEC_OFFSET)

static void log_error_regs(struct m10bmc_sec *sec, u32 doorbell)
{
	u32 auth_result;

	dev_err(sec->dev, "RSU error status: 0x%08x\n", doorbell);

	if (!m10bmc_sys_read(sec->m10bmc, M10BMC_AUTH_RESULT, &auth_result))
		dev_err(sec->dev, "RSU auth result: 0x%08x\n", auth_result);
}

static enum ifpga_sec_err rsu_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return IFPGA_SEC_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_IDLE &&
	    rsu_prog(doorbell) != RSU_PROG_RSU_DONE) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_BUSY;
	}

	return IFPGA_SEC_ERR_NONE;
}

static inline bool rsu_start_done(u32 doorbell)
{
	return (!(doorbell & RSU_REQUEST) &&
		(rsu_stat(doorbell) == RSU_STAT_ERASE_FAIL ||
		rsu_stat(doorbell) == RSU_STAT_WEAROUT ||
		(rsu_prog(doorbell) != RSU_PROG_IDLE &&
		 rsu_prog(doorbell) != RSU_PROG_RSU_DONE)));
}

static enum ifpga_sec_err rsu_update_init(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     RSU_REQUEST | HOST_STATUS, RSU_REQUEST |
				     FIELD_PREP(HOST_STATUS, HOST_STATUS_IDLE));
	if (ret)
		return IFPGA_SEC_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       doorbell,
				       rsu_start_done(doorbell),
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	if (rsu_stat(doorbell) == RSU_STAT_WEAROUT) {
		dev_warn(sec->dev, "Excessive flash count detected\n");
		return IFPGA_SEC_ERR_WEAROUT;
	} else if (rsu_stat(doorbell) == RSU_STAT_ERASE_FAIL) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	return IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err rsu_prog_ready(struct m10bmc_sec *sec)
{
	unsigned long poll_timeout;
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	poll_timeout = jiffies + msecs_to_jiffies(RSU_PREP_TIMEOUT_MS);
	while (!ret && !time_after(jiffies, poll_timeout)) {
		if (rsu_prog(doorbell) != RSU_PROG_PREPARE)
			break;
		msleep(RSU_PREP_INTERVAL_MS);
		ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	}

	if (ret) {
		return IFPGA_SEC_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) == RSU_PROG_PREPARE) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	return IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err rsu_send_data(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL, HOST_STATUS,
				     FIELD_PREP(HOST_STATUS,
						HOST_STATUS_WRITE_DONE));
	if (ret)
		return IFPGA_SEC_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       doorbell,
				       rsu_prog(doorbell) != RSU_PROG_READY,
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	switch (rsu_stat(doorbell)) {
	case RSU_STAT_NORMAL:
	case RSU_STAT_NIOS_OK:
	case RSU_STAT_USER_OK:
	case RSU_STAT_FACTORY_OK:
		break;
	default:
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	return IFPGA_SEC_ERR_NONE;
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

static enum ifpga_sec_err m10bmc_sec_prepare(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
	enum ifpga_sec_err ret;

	if (imgr->remaining_size > M10BMC_STAGING_SIZE)
		return IFPGA_SEC_ERR_INVALID_SIZE;

	ret = rsu_check_idle(sec);
	if (ret)
		return ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return IFPGA_SEC_ERR_BUSY;

	ret = rsu_update_init(sec);
	if (ret)
		goto fw_state_exit;

	ret = rsu_prog_ready(sec);

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return ret;
}

static enum ifpga_sec_err
m10bmc_sec_write_blk(struct ifpga_sec_mgr *imgr, u32 offset, u32 size)
{
	struct m10bmc_sec *sec = imgr->priv;
	unsigned int stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret) {
		return IFPGA_SEC_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	ret = m10bmc_raw_bulk_write(sec->m10bmc, M10BMC_STAGING_BASE + offset,
				    (void *)imgr->data + offset, size / stride);

	return ret ? IFPGA_SEC_ERR_RW_ERROR : IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err m10bmc_sec_poll_complete(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
	unsigned long poll_timeout;
	enum ifpga_sec_err result;
	u32 doorbell;
	int ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return IFPGA_SEC_ERR_BUSY;

	result = rsu_send_data(sec);
	if (result)
		goto fw_state_exit;

	ret = rsu_check_complete(sec, &doorbell);
	poll_timeout = jiffies + msecs_to_jiffies(RSU_COMPLETE_TIMEOUT_MS);
	while (ret == -EAGAIN && !time_after(jiffies, poll_timeout)) {
		msleep(RSU_COMPLETE_INTERVAL_MS);
		ret = rsu_check_complete(sec, &doorbell);
		if (imgr->driver_unload) {
			result = IFPGA_SEC_ERR_CANCELED;
			goto fw_state_exit;
		}
	}

	if (ret == -EAGAIN) {
		log_error_regs(sec, doorbell);
		result = IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret == -EIO) {
		result = IFPGA_SEC_ERR_RW_ERROR;
	} else if (ret) {
		log_error_regs(sec, doorbell);
		result = IFPGA_SEC_ERR_HW_ERROR;
	}

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return result;
}

static enum ifpga_sec_err m10bmc_sec_cancel(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
	if (ret)
		return IFPGA_SEC_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_READY)
		return IFPGA_SEC_ERR_BUSY;

	ret = m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL, HOST_STATUS,
				     FIELD_PREP(HOST_STATUS,
						HOST_STATUS_ABORT_RSU));

	return ret ? IFPGA_SEC_ERR_RW_ERROR : IFPGA_SEC_ERR_NONE;
}

static u64 m10bmc_sec_hw_errinfo(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
	u32 doorbell = 0, auth_result = 0;
	u64 hw_errinfo = 0;

	switch (imgr->err_code) {
	case IFPGA_SEC_ERR_HW_ERROR:
	case IFPGA_SEC_ERR_TIMEOUT:
	case IFPGA_SEC_ERR_BUSY:
	case IFPGA_SEC_ERR_WEAROUT:
		if (!m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell))
			hw_errinfo = (u64)doorbell << 32;

		if (!m10bmc_sys_read(sec->m10bmc, M10BMC_AUTH_RESULT,
				     &auth_result))
			hw_errinfo |= (u64)auth_result;

		return hw_errinfo;
	default:
		return 0;
	}
}

static int m10bmc_sec_bmc_image_load(struct ifpga_sec_mgr *imgr,
				     unsigned int val)
{
	struct m10bmc_sec *sec = imgr->priv;
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

	if (doorbell & REBOOT_DISABLED)
		return -EBUSY;

	return m10bmc_sys_update_bits(sec->m10bmc, M10BMC_DOORBELL,
				     CONFIG_SEL | REBOOT_REQ,
				     FIELD_PREP(CONFIG_SEL, val) |
				     REBOOT_REQ);
}

static int m10bmc_sec_bmc_image_load_0(struct ifpga_sec_mgr *imgr)
{
	return m10bmc_sec_bmc_image_load(imgr, 0);
}

static int m10bmc_sec_bmc_image_load_1(struct ifpga_sec_mgr *imgr)
{
	return m10bmc_sec_bmc_image_load(imgr, 1);
}

static int retimer_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_DOORBELL, &doorbell);
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

	ret = m10bmc_sys_update_bits(m10bmc, M10BMC_DOORBELL,
				     PKVL_EEPROM_LOAD_SEC,
				     PKVL_EEPROM_LOAD_SEC);
	if (ret)
		return ret;

	/*
	 * If the current NIOS FW supports this retimer update feature, then
	 * it will clear the same PKVL_EEPROM_LOAD bit in 2 seconds. Otherwise
	 * the driver needs to clear the PKVL_EEPROM_LOAD bit manually and
	 * return an error code.
	 */
	ret = regmap_read_poll_timeout(m10bmc->regmap,
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       val, (!(val & PKVL_EEPROM_LOAD_SEC)),
				       PKVL_EEPROM_LOAD_INTERVAL_US,
				       PKVL_EEPROM_LOAD_TIMEOUT_US);
	if (ret == -ETIMEDOUT) {
		dev_err(sec->dev, "%s PKVL_EEPROM_LOAD clear timedout\n",
			__func__);
		m10bmc_sys_update_bits(m10bmc, M10BMC_DOORBELL,
				       PKVL_EEPROM_LOAD_SEC, 0);
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
				       M10BMC_SYS_BASE + M10BMC_DOORBELL,
				       doorbell,
				       ((rsu_prog(doorbell) ==
					 RSU_PROG_PKVL_PROM_DONE) ||
					(rsu_stat(doorbell) ==
					 RSU_STAT_PKVL_REJECT)),
				       PKVL_PRELOAD_INTERVAL_US,
				       PKVL_PRELOAD_TIMEOUT_US);
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
				       M10BMC_SYS_BASE + PKVL_POLLING_CTRL, val,
				       ((val & PKVL_PRELOAD) == PKVL_PRELOAD),
				       PKVL_PRELOAD_INTERVAL_US,
				       PKVL_PRELOAD_TIMEOUT_US);
	if (ret) {
		dev_err(sec->dev, "%s poll PKVL_PRELOAD error %d\n",
			__func__, ret);
		return ret;
	}

	if ((val & PKVL_UPG_STATUS_MASK) != PKVL_UPG_STATUS_GOOD) {
		dev_err(sec->dev, "%s error detected during upgrade\n",
			__func__);
		return -EIO;
	}

	return 0;
}

static int m10bmc_sec_retimer_eeprom_load(struct ifpga_sec_mgr *imgr)
{
	struct m10bmc_sec *sec = imgr->priv;
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

static void ifpga_sec_mgr_uinit(struct m10bmc_sec *sec)
{
	ifpga_sec_mgr_unregister(sec->imgr);
}

static int ifpga_sec_mgr_init(struct m10bmc_sec *sec,
			      struct ifpga_sec_mgr_ops *iops)
{
	struct ifpga_sec_mgr *imgr;

	imgr = ifpga_sec_mgr_register(sec->dev, "Max10 BMC Security Manager",
				      iops, sec);
	if (IS_ERR(imgr))
		return PTR_ERR(imgr);

	sec->imgr = imgr;
	return 0;
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

static struct ifpga_sec_mgr_ops *
m10bmc_iops_create(struct device *dev, enum m10bmc_type type)
{
	struct ifpga_sec_mgr_ops *iops;

	iops = devm_kzalloc(dev, sizeof(*iops), GFP_KERNEL);
	if (!iops)
		return NULL;

	iops->user_flash_count = get_qspi_flash_count;
	iops->bmc_root_entry_hash = get_bmc_root_entry_hash;
	iops->sr_root_entry_hash = get_sr_root_entry_hash;
	iops->pr_root_entry_hash = get_pr_root_entry_hash;
	iops->bmc_canceled_csks = get_bmc_canceled_csks;
	iops->sr_canceled_csks = get_sr_canceled_csks;
	iops->pr_canceled_csks = get_pr_canceled_csks;
	iops->bmc_reh_size = get_bmc_reh_size;
	iops->sr_reh_size = get_sr_reh_size;
	iops->pr_reh_size = get_pr_reh_size;
	iops->bmc_canceled_csk_nbits = get_bmc_csk_cancel_nbits;
	iops->sr_canceled_csk_nbits = get_sr_csk_cancel_nbits;
	iops->pr_canceled_csk_nbits = get_pr_csk_cancel_nbits;
	iops->prepare = m10bmc_sec_prepare;
	iops->write_blk = m10bmc_sec_write_blk;
	iops->poll_complete = m10bmc_sec_poll_complete;
	iops->cancel = m10bmc_sec_cancel;
	iops->get_hw_errinfo = m10bmc_sec_hw_errinfo;

	if (type == M10_N3000)
		iops->image_load = n3000_image_load_hndlrs;
	else 
		iops->image_load = d5005_image_load_hndlrs;

	return iops;
}

static int m10bmc_secure_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	enum m10bmc_type type = (enum m10bmc_type)id->driver_data;
	struct ifpga_sec_mgr_ops *iops;
	struct m10bmc_sec *sec;
	int ret;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	iops = m10bmc_iops_create(&pdev->dev, type);
	if (!iops)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	dev_set_drvdata(&pdev->dev, sec);

	ret = ifpga_sec_mgr_init(sec, iops);
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

static const struct platform_device_id intel_m10bmc_secure_ids[] = {
	{
		.name = "n3000bmc-secure",
		.driver_data = (unsigned long)M10_N3000,
	},
	{
		.name = "d5005bmc-secure",
		.driver_data = (unsigned long)M10_D5005,
	},
	{ }
};

static struct platform_driver intel_m10bmc_secure_driver = {
	.probe = m10bmc_secure_probe,
	.remove = m10bmc_secure_remove,
	.driver = {
		.name = "intel-m10bmc-secure",
	},
	.id_table = intel_m10bmc_secure_ids,
};
module_platform_driver(intel_m10bmc_secure_driver);

MODULE_DEVICE_TABLE(platform, intel_m10bmc_secure_ids);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC secure engine");
MODULE_LICENSE("GPL v2");
