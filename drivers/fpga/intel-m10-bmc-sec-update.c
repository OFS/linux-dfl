// SPDX-License-Identifier: GPL-2.0
/*
 * Intel MAX10 Board Management Controller Secure Update Driver
 *
 * Copyright (C) 2019-2022 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct m10bmc_sec;

/* Supported fpga secure manager types */
enum fpga_sec_type {
	N3000BMC_SEC,
	D5005BMC_SEC,
	N5010BMC_SEC,
	N6000BMC_SEC
};

/* Supported names for power-on images */
enum fpga_image {
	FPGA_FACTORY,
	FPGA_USER1,
	FPGA_USER2,
	FPGA_MAX
};

static const char * const fpga_image_names[] = {
	[FPGA_FACTORY] = "fpga_factory",
	[FPGA_USER1] = "fpga_user1",
	[FPGA_USER2] = "fpga_user2"
};

struct fpga_power_on {
	u32 avail_image_mask;
	int (*get_sequence)(struct m10bmc_sec *sec, char *buf);
	int (*set_sequence)(struct m10bmc_sec *sec, enum fpga_image images[]);
};

struct image_load;

struct m10bmc_sec {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	struct fw_upload *fwl;
	char *fw_name;
	u32 fw_name_id;
	bool cancel_request;
	struct image_load *image_load;		/* terminated with { } member */
	enum fpga_sec_type type;
	const struct fpga_power_on *poc;	/* power on image configuration */
};

struct image_load {
	const char *name;
	int (*load_image)(struct m10bmc_sec *sec);
};

static void log_error_regs(struct m10bmc_sec *sec, u32 doorbell)
{
	u32 auth_result;

	dev_err(sec->dev, "RSU error status: 0x%08x\n", doorbell);

	if (!m10bmc_sys_read(sec->m10bmc, auth_result_reg(sec->m10bmc), &auth_result))
		dev_err(sec->dev, "RSU auth result: 0x%08x\n", auth_result);
}

static int m10bmc_sec_bmc_image_load(struct m10bmc_sec *sec,
				     unsigned int val)
{
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

	switch (sec->type) {
	case N3000BMC_SEC:
	case D5005BMC_SEC:
	case N5010BMC_SEC:
		if (doorbell & DRBL_REBOOT_DISABLED)
			return -EBUSY;

		return m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
					      DRBL_CONFIG_SEL | DRBL_REBOOT_REQ,
					      FIELD_PREP(DRBL_CONFIG_SEL, val) |
					      DRBL_REBOOT_REQ);
	case N6000BMC_SEC:
		if (doorbell & PMCI_DRBL_REBOOT_DISABLED)
			return -EBUSY;

		return regmap_update_bits(sec->m10bmc->regmap,
					  m10bmc_base(sec->m10bmc) +
					  M10BMC_PMCI_MAX10_RECONF,
					  PMCI_MAX10_REBOOT_REQ | PMCI_MAX10_REBOOT_PAGE,
					  FIELD_PREP(PMCI_MAX10_REBOOT_PAGE, val) |
					  PMCI_MAX10_REBOOT_REQ);

	default:
		return -EINVAL;
	}
}

static int pmci_sec_fpga_image_load(struct m10bmc_sec *sec,
				    unsigned int val)
{
	int ret;

	if (val > 2) {
		dev_err(sec->dev, "%s invalid reload val = %d\n",
			__func__, val);
		return -EINVAL;
	}

	ret = regmap_update_bits(sec->m10bmc->regmap,
				 m10bmc_base(sec->m10bmc) + M10BMC_PMCI_FPGA_RECONF,
				 PMCI_FPGA_RP_LOAD, 0);
	if (ret)
		return ret;

	return regmap_update_bits(sec->m10bmc->regmap,
				  m10bmc_base(sec->m10bmc) +
				  M10BMC_PMCI_FPGA_RECONF,
				  PMCI_FPGA_RECONF_PAGE | PMCI_FPGA_RP_LOAD,
				  FIELD_PREP(PMCI_FPGA_RECONF_PAGE, val) |
				  PMCI_FPGA_RP_LOAD);
}

static int m10bmc_sec_bmc_image_load_0(struct m10bmc_sec *sec)
{
	return m10bmc_sec_bmc_image_load(sec, 0);
}

static int m10bmc_sec_bmc_image_load_1(struct m10bmc_sec *sec)
{
	return m10bmc_sec_bmc_image_load(sec, 1);
}

static int pmci_sec_bmc_image_load_0(struct m10bmc_sec *sec)
{
	return m10bmc_sec_bmc_image_load(sec, 0);
}

static int pmci_sec_bmc_image_load_1(struct m10bmc_sec *sec)
{
	return m10bmc_sec_bmc_image_load(sec, 1);
}

static int pmci_sec_fpga_image_load_0(struct m10bmc_sec *sec)
{
	return pmci_sec_fpga_image_load(sec, 0);
}

static int pmci_sec_fpga_image_load_1(struct m10bmc_sec *sec)
{
	return pmci_sec_fpga_image_load(sec, 1);
}

static int pmci_sec_fpga_image_load_2(struct m10bmc_sec *sec)
{
	return pmci_sec_fpga_image_load(sec, 2);
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

static int m10bmc_sec_retimer_eeprom_load(struct m10bmc_sec *sec)
{
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

static struct image_load pmci_image_load_hndlrs[] = {
	{
		.name = "bmc_factory",
		.load_image = pmci_sec_bmc_image_load_0,
	},
	{
		.name = "bmc_user",
		.load_image = pmci_sec_bmc_image_load_1,
	},
	{
		.name = "fpga_factory",
		.load_image = pmci_sec_fpga_image_load_0,
	},
	{
		.name = "fpga_user1",
		.load_image = pmci_sec_fpga_image_load_1,
	},
	{
		.name = "fpga_user2",
		.load_image = pmci_sec_fpga_image_load_2,
	},
	{}
};

static DEFINE_XARRAY_ALLOC(fw_upload_xa);

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
	int sha_num_bytes, i, ret, cnt = 0;
	u8 hash[REH_SHA384_SIZE];
	u32 magic;

	if (sec->type == N6000BMC_SEC) {
		ret = sec->m10bmc->ops.flash_read(sec->m10bmc, &magic,
						  prog_addr, sizeof(u32));
	} else {
		ret = m10bmc_raw_read(sec->m10bmc, prog_addr, &magic);
	}

	if (ret)
		return ret;

	if (FIELD_GET(REH_MAGIC, magic) != exp_magic)
		return sysfs_emit(buf, "hash not programmed\n");

	sha_num_bytes = FIELD_GET(REH_SHA_NUM_BYTES, magic) / 8;
	if (sha_num_bytes != REH_SHA256_SIZE &&
	    sha_num_bytes != REH_SHA384_SIZE) {
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

	for (i = 0; i < sha_num_bytes; i++)
		cnt += sprintf(buf + cnt, "%02x", hash[i]);
	cnt += sprintf(buf + cnt, "\n");

	return cnt;
}

#define DEVICE_ATTR_SEC_REH_RO(_name) \
static ssize_t _name##_root_entry_hash_show(struct device *dev, \
					    struct device_attribute *attr, \
					    char *buf) \
{							\
	struct m10bmc_sec *sec = dev_get_drvdata(dev);   \
	struct intel_m10bmc *m10bmc = sec->m10bmc;  \
	return show_root_entry_hash(dev, _name##_magic(m10bmc),\
			_name##_prog_addr(m10bmc), _name##_reh_addr(m10bmc),\
			buf); } \
static DEVICE_ATTR_RO(_name##_root_entry_hash)

DEVICE_ATTR_SEC_REH_RO(bmc);
DEVICE_ATTR_SEC_REH_RO(sr);
DEVICE_ATTR_SEC_REH_RO(pr);

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

#define DEVICE_ATTR_SEC_CSK_RO(_name) \
static ssize_t _name##_canceled_csks_show(struct device *dev, \
					  struct device_attribute *attr, \
					  char *buf) \
{                                                    \
	struct m10bmc_sec *sec = dev_get_drvdata(dev);   \
	struct intel_m10bmc *m10bmc = sec->m10bmc;  \
	return show_canceled_csk(dev, _name##_prog_addr(m10bmc) + CSK_VEC_OFFSET,\
			buf); } \
static DEVICE_ATTR_RO(_name##_canceled_csks)

#define CSK_VEC_OFFSET 0x34

DEVICE_ATTR_SEC_CSK_RO(bmc);
DEVICE_ATTR_SEC_CSK_RO(sr);
DEVICE_ATTR_SEC_CSK_RO(pr);

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
					  rsu_update_counter(sec->m10bmc),
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

static enum fpga_image
fpga_image_by_name(struct m10bmc_sec *sec, char *image_name)
{
	enum fpga_image i;

	for (i = 0; i < FPGA_MAX; i++)
		if (sysfs_streq(image_name, fpga_image_names[i]))
			return i;

	return FPGA_MAX;
}

static int
fpga_images(struct m10bmc_sec *sec, char *names, enum fpga_image images[])
{
	u32 image_mask = sec->poc->avail_image_mask;
	enum fpga_image image;
	char *image_name;
	int i = 0;

	while ((image_name = strsep(&names, " \n"))) {
		image = fpga_image_by_name(sec, image_name);
		if (image >= FPGA_MAX || !(image_mask & BIT(image)))
			return -EINVAL;

		images[i++] = image;
		image_mask &= ~BIT(image);
	}

	return (i == 0) ? -EINVAL : 0;
}

static int
pmci_set_power_on_image(struct m10bmc_sec *sec, enum fpga_image images[])
{
	u32 poc_mask = PMCI_FACTORY_IMAGE_SEL|PMCI_USER_IMAGE_PAGE;
	int ret, first_user = 0;
	u32 val, poc = 0;

	if (images[1] == FPGA_FACTORY)
		return -EINVAL;

	if (images[0] == FPGA_FACTORY) {
		poc = PMCI_FACTORY_IMAGE_SEL;
		first_user = 1;
	}

	if (images[first_user] == FPGA_USER1 || images[first_user] == FPGA_USER2) {
		if (images[first_user] == FPGA_USER1)
			poc |= FIELD_PREP(PMCI_USER_IMAGE_PAGE, POC_USER_IMAGE_1);
		else
			poc |= FIELD_PREP(PMCI_USER_IMAGE_PAGE, POC_USER_IMAGE_2);
	} else {
		dev_dbg(sec->dev, "%s first_user = %d not USER1 or USER2\n", __func__, first_user);
		ret = m10bmc_sys_read(sec->m10bmc, M10BMC_PMCI_FPGA_POC_STS_BL, &val);
		if (ret)
			return ret;

		if  (FIELD_GET(PMCI_USER_IMAGE_PAGE, val) == POC_USER_IMAGE_1)
			poc |= FIELD_PREP(PMCI_USER_IMAGE_PAGE, POC_USER_IMAGE_1);
		else
			poc |= FIELD_PREP(PMCI_USER_IMAGE_PAGE, POC_USER_IMAGE_2);
	}

	dev_dbg(sec->dev, "%s poc = 0x%x pock_mask = 0x%x\n", __func__, poc, poc_mask);

	ret = m10bmc_sys_update_bits(sec->m10bmc,
				     m10bmc_base(sec->m10bmc) + M10BMC_PMCI_FPGA_POC,
				     poc_mask | PMCI_FPGA_POC, poc | PMCI_FPGA_POC);
	if (ret) {
		dev_err(sec->dev, "%s m10bmc_sys_update_bits failed %d\n", __func__, ret);
		return ret;
	}

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       m10bmc_base(sec->m10bmc) + M10BMC_PMCI_FPGA_POC,
				       poc,
				       (!(poc & PMCI_FPGA_POC)),
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret || (FIELD_GET(PMCI_NIOS_STATUS, poc) != NIOS_STATUS_SUCCESS)) {
		dev_err(sec->dev, "%s readback poc = 0x%x\n", __func__, poc);
		return -EIO;
	}

	return 0;
}

static int pmci_get_power_on_image(struct m10bmc_sec *sec, char *buf)
{
	const char *image_names[FPGA_MAX] = { 0 };
	int ret, i = 0;
	u32 poc;

	ret = m10bmc_sys_read(sec->m10bmc, M10BMC_PMCI_FPGA_POC_STS_BL, &poc);
	if (ret)
		return ret;

	if (poc & PMCI_FACTORY_IMAGE_SEL)
		image_names[i++] = fpga_image_names[FPGA_FACTORY];

	if (FIELD_GET(PMCI_USER_IMAGE_PAGE, poc) == POC_USER_IMAGE_1) {
		image_names[i++] = fpga_image_names[FPGA_USER1];
		image_names[i++] = fpga_image_names[FPGA_USER2];
	} else {
		image_names[i++] = fpga_image_names[FPGA_USER2];
		image_names[i++] = fpga_image_names[FPGA_USER1];
	}

	if (!(poc & PMCI_FACTORY_IMAGE_SEL))
		image_names[i] = fpga_image_names[FPGA_FACTORY];

	return sysfs_emit(buf, "%s %s %s\n", image_names[0],
			  image_names[1], image_names[2]);
}

static ssize_t
available_power_on_images_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	ssize_t count = 0;
	enum fpga_image i;

	for (i = 0; i < FPGA_MAX; i++)
		if (BIT(i) & sec->poc->avail_image_mask)
			count += scnprintf(buf + count, PAGE_SIZE - count,
					   "%s ", fpga_image_names[i]);
	buf[count - 1] = '\n';

	return count;
}
static DEVICE_ATTR_RO(available_power_on_images);

static ssize_t
power_on_image_show(struct device *dev,
		    struct device_attribute *attr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);

	return sec->poc->get_sequence(sec, buf);
}

static ssize_t
power_on_image_store(struct device *dev,
		     struct device_attribute *attr, const char *buf, size_t count)
{
	enum fpga_image images[FPGA_MAX] = { [0 ... FPGA_MAX - 1] = FPGA_MAX };
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	char *tokens;
	int ret;

	tokens = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!tokens)
		ret = -ENOMEM;

	ret = fpga_images(sec, tokens, images);
	if (ret)
		goto free_exit;

	ret = sec->poc->set_sequence(sec, images);

free_exit:
	kfree(tokens);
	return ret ? : count;
}
static DEVICE_ATTR_RW(power_on_image);

static ssize_t
fpga_boot_image_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	int ret;
	u32 status;
	int boot_page;

	ret = m10bmc_sys_read(sec->m10bmc, m10bmc_base(sec->m10bmc) +
			      M10BMC_PMCI_FPGA_CONF_STS, &status);
	if (ret)
		return ret;

	if (!FIELD_GET(PMCI_FPGA_CONFIGED, status))
		return -EINVAL;

	boot_page = FIELD_GET(PMCI_FPGA_BOOT_PAGE, status);
	if (boot_page >= FPGA_MAX)
		return -EINVAL;

	return sysfs_emit(buf, "%s\n", fpga_image_names[boot_page]);
}
static DEVICE_ATTR_RO(fpga_boot_image);

static const struct fpga_power_on pmci_power_on_image = {
	.avail_image_mask = BIT(FPGA_FACTORY) | BIT(FPGA_USER1) | BIT(FPGA_USER2),
	.set_sequence = pmci_set_power_on_image,
	.get_sequence = pmci_get_power_on_image,
};

static ssize_t available_images_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	const struct image_load *hndlr;
	ssize_t count = 0;

	for (hndlr = sec->image_load; hndlr->name; hndlr++) {
		count += scnprintf(buf + count, PAGE_SIZE - count,
				   "%s ", hndlr->name);
	}

	buf[count - 1] = '\n';

	return count;
}
static DEVICE_ATTR_RO(available_images);

static ssize_t image_load_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct m10bmc_sec *sec = dev_get_drvdata(dev);
	const struct image_load *hndlr;
	int ret = -EINVAL;

	for (hndlr = sec->image_load; hndlr->name; hndlr++) {
		if (sysfs_streq(buf, hndlr->name)) {
			ret = hndlr->load_image(sec);
			break;
		}
	}

	return ret ? : count;
}
static DEVICE_ATTR_WO(image_load);

static umode_t
m10bmc_is_visible(struct kobject *kobj,
		  struct attribute *attr, int n)
{
	struct m10bmc_sec *sec = dev_get_drvdata(kobj_to_dev(kobj));

	if ((sec->type != N6000BMC_SEC) &&
	    (attr == &dev_attr_power_on_image.attr ||
	     attr == &dev_attr_available_power_on_images.attr ||
	     attr == &dev_attr_fpga_boot_image.attr))
		return 0;

	return attr->mode;
}

static struct attribute *m10bmc_control_attrs[] = {
	&dev_attr_available_images.attr,
	&dev_attr_image_load.attr,
	&dev_attr_power_on_image.attr,
	&dev_attr_available_power_on_images.attr,
	&dev_attr_fpga_boot_image.attr,
	NULL,
};

static struct attribute_group m10bmc_control_attr_group = {
	.name = "control",
	.attrs = m10bmc_control_attrs,
	.is_visible = m10bmc_is_visible,
};

static const struct attribute_group *m10bmc_sec_attr_groups[] = {
	&m10bmc_security_attr_group,
	&m10bmc_control_attr_group,
	NULL,
};

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

	reg_offset = (sec->type == N6000BMC_SEC) ?
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

	if (sec->type == N6000BMC_SEC) {
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

static enum fw_upload_err rsu_check_idle(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	if (!rsu_progress_done(rsu_prog(doorbell))) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_BUSY;
	}

	return FW_UPLOAD_ERR_NONE;
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

	poll_timeout = jiffies + usecs_to_jiffies(NIOS_HANDSHAKE_TIMEOUT_US);
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

static enum fw_upload_err rsu_update_init(struct m10bmc_sec *sec)
{
	u32 doorbell, progress, status;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_RSU_REQUEST | DRBL_HOST_STATUS,
				     DRBL_RSU_REQUEST |
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_IDLE));
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	ret = rsu_poll_start_done(sec, &doorbell, &progress, &status);
	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_TIMEOUT;
	} else if (ret) {
		return FW_UPLOAD_ERR_RW_ERROR;
	}

	if (status == RSU_STAT_WEAROUT) {
		dev_warn(sec->dev, "Excessive flash update count detected\n");
		return FW_UPLOAD_ERR_WEAROUT;
	} else if (status == RSU_STAT_ERASE_FAIL) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err rsu_prog_ready(struct m10bmc_sec *sec)
{
	unsigned long poll_timeout;
	u32 doorbell, progress;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	poll_timeout = jiffies + msecs_to_jiffies(RSU_PREP_TIMEOUT_MS);
	while (rsu_prog(doorbell) == RSU_PROG_PREPARE) {
		msleep(RSU_PREP_INTERVAL_MS);
		if (time_after(jiffies, poll_timeout))
			break;

		ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
		if (ret)
			return FW_UPLOAD_ERR_RW_ERROR;
	}

	progress = rsu_prog(doorbell);
	if (progress == RSU_PROG_PREPARE) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_TIMEOUT;
	} else if (progress != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err rsu_send_data(struct m10bmc_sec *sec)
{
	u32 doorbell, status;
	int ret;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_WRITE_DONE));
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	ret = regmap_read_poll_timeout(sec->m10bmc->regmap,
				       m10bmc_base(sec->m10bmc) + doorbell_reg(sec->m10bmc),
				       doorbell,
				       rsu_prog(doorbell) != RSU_PROG_READY,
				       NIOS_HANDSHAKE_INTERVAL_US,
				       NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret == -ETIMEDOUT) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_TIMEOUT;
	} else if (ret) {
		return FW_UPLOAD_ERR_RW_ERROR;
	}

	ret = m10bmc_sec_status(sec, &status);
	if (ret)
		return FW_UPLOAD_ERR_HW_ERROR;

	if (!rsu_status_ok(status)) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	return FW_UPLOAD_ERR_NONE;
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

static enum fw_upload_err rsu_cancel(struct m10bmc_sec *sec)
{
	u32 doorbell;
	int ret;

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	if (rsu_prog(doorbell) != RSU_PROG_READY)
		return FW_UPLOAD_ERR_BUSY;

	ret = m10bmc_sys_update_bits(sec->m10bmc, doorbell_reg(sec->m10bmc),
				     DRBL_HOST_STATUS,
				     FIELD_PREP(DRBL_HOST_STATUS,
						HOST_STATUS_ABORT_RSU));
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	return FW_UPLOAD_ERR_CANCELED;
}

static enum fw_upload_err m10bmc_sec_prepare(struct fw_upload *fwl,
					     const u8 *data, u32 size)
{
	struct m10bmc_sec *sec = fwl->dd_handle;
	u32 ret;

	sec->cancel_request = false;

	if (!size || size > M10BMC_STAGING_SIZE)
		return FW_UPLOAD_ERR_INVALID_SIZE;

	ret = rsu_check_idle(sec);
	if (ret != FW_UPLOAD_ERR_NONE)
		return ret;

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return FW_UPLOAD_ERR_BUSY;

	ret = rsu_update_init(sec);
	if (ret != FW_UPLOAD_ERR_NONE)
		goto fw_state_exit;

	ret = rsu_prog_ready(sec);
	if (ret != FW_UPLOAD_ERR_NONE)
		goto fw_state_exit;

	if (sec->cancel_request)
		ret = rsu_cancel(sec);

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return ret;
}

#define WRITE_BLOCK_SIZE 0x4000	/* Default write-block size is 0x4000 bytes */

static enum fw_upload_err m10bmc_sec_write(struct fw_upload *fwl, const u8 *data,
					   u32 offset, u32 size, u32 *written)
{
	struct m10bmc_sec *sec = fwl->dd_handle;
	u32 blk_size, doorbell, extra_offset;
	unsigned int stride, extra = 0;
	int ret;

	stride = regmap_get_reg_stride(sec->m10bmc->regmap);
	if (sec->cancel_request)
		return rsu_cancel(sec);

	ret = m10bmc_sys_read(sec->m10bmc, doorbell_reg(sec->m10bmc), &doorbell);
	if (ret) {
		return FW_UPLOAD_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	WARN_ON_ONCE(WRITE_BLOCK_SIZE % stride);
	blk_size = min_t(u32, WRITE_BLOCK_SIZE, size);
	ret = regmap_bulk_write(sec->m10bmc->regmap,
				M10BMC_STAGING_BASE + offset,
				(void *)data + offset,
				blk_size / stride);
	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	/*
	 * If blk_size is not aligned to stride, then handle the extra
	 * bytes with regmap_write.
	 */
	if (blk_size % stride) {
		extra_offset = offset + ALIGN_DOWN(blk_size, stride);
		memcpy(&extra, (u8 *)(data + extra_offset), blk_size % stride);
		ret = regmap_write(sec->m10bmc->regmap,
				   M10BMC_STAGING_BASE + extra_offset, extra);
		if (ret)
			return FW_UPLOAD_ERR_RW_ERROR;
	}

	*written = blk_size;
	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err pmci_sec_write(struct fw_upload *fwl, const u8 *data,
					 u32 offset, u32 size, u32 *written)
{
	struct m10bmc_sec *sec = fwl->dd_handle;
	struct intel_m10bmc *m10bmc;
	u32 blk_size, doorbell;
	int ret;

	m10bmc = sec->m10bmc;

	if (sec->cancel_request)
		return rsu_cancel(sec);

	ret = m10bmc_sys_read(m10bmc, doorbell_reg(m10bmc), &doorbell);
	if (ret) {
		return FW_UPLOAD_ERR_RW_ERROR;
	} else if (rsu_prog(doorbell) != RSU_PROG_READY) {
		log_error_regs(sec, doorbell);
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	blk_size = min_t(u32, WRITE_BLOCK_SIZE, size);
	ret = m10bmc->flash_ops->write_blk(m10bmc, (void *)data + offset,
					   blk_size);

	if (ret)
		return FW_UPLOAD_ERR_RW_ERROR;

	*written = blk_size;
	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err m10bmc_sec_poll_complete(struct fw_upload *fwl)
{
	struct m10bmc_sec *sec = fwl->dd_handle;
	unsigned long poll_timeout;
	u32 doorbell, result;
	int ret;

	if (sec->cancel_request)
		return rsu_cancel(sec);

	ret = m10bmc_fw_state_enter(sec->m10bmc, M10BMC_FW_STATE_SEC_UPDATE);
	if (ret)
		return FW_UPLOAD_ERR_BUSY;

	result = rsu_send_data(sec);
	if (result != FW_UPLOAD_ERR_NONE)
		goto fw_state_exit;

	poll_timeout = jiffies + msecs_to_jiffies(RSU_COMPLETE_TIMEOUT_MS);
	do {
		msleep(RSU_COMPLETE_INTERVAL_MS);
		ret = rsu_check_complete(sec, &doorbell);
	} while (ret == -EAGAIN && !time_after(jiffies, poll_timeout));

	if (ret == -EAGAIN) {
		log_error_regs(sec, doorbell);
		result = FW_UPLOAD_ERR_TIMEOUT;
	} else if (ret == -EIO) {
		result = FW_UPLOAD_ERR_RW_ERROR;
	} else if (ret) {
		log_error_regs(sec, doorbell);
		result = FW_UPLOAD_ERR_HW_ERROR;
	}

fw_state_exit:
	m10bmc_fw_state_exit(sec->m10bmc);
	return result;
}

/*
 * m10bmc_sec_cancel() may be called asynchronously with an on-going update.
 * All other functions are called sequentially in a single thread. To avoid
 * contention on register accesses, m10bmc_sec_cancel() must only update
 * the cancel_request flag. Other functions will check this flag and handle
 * the cancel request synchronously.
 */
static void m10bmc_sec_cancel(struct fw_upload *fwl)
{
	struct m10bmc_sec *sec = fwl->dd_handle;

	sec->cancel_request = true;
}

static void m10bmc_sec_cleanup(struct fw_upload *fwl)
{
	struct m10bmc_sec *sec = fwl->dd_handle;

	(void)rsu_cancel(sec);
}

static struct fw_upload_ops *
m10bmc_ops_create(struct device *dev, enum fpga_sec_type type)
{
	struct fw_upload_ops *ops;

	ops = devm_kzalloc(dev, sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return NULL;

	ops->prepare = m10bmc_sec_prepare;
	ops->poll_complete = m10bmc_sec_poll_complete;
	ops->cancel = m10bmc_sec_cancel;
	ops->cleanup = m10bmc_sec_cleanup;

	if (type == N6000BMC_SEC)
		ops->write = pmci_sec_write;
	else
		ops->write = m10bmc_sec_write;

	return ops;
}

#define SEC_UPDATE_LEN_MAX 32
static int m10bmc_sec_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	enum fpga_sec_type type = (enum fpga_sec_type)id->driver_data;
	char buf[SEC_UPDATE_LEN_MAX];
	struct fw_upload_ops *ops;
	struct m10bmc_sec *sec;
	struct fw_upload *fwl;
	unsigned int len;
	int  ret;

	sec = devm_kzalloc(&pdev->dev, sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	ops = m10bmc_ops_create(&pdev->dev, type);
	if (!ops)
		return -ENOMEM;

	sec->dev = &pdev->dev;
	sec->m10bmc = dev_get_drvdata(pdev->dev.parent);
	sec->type = type;

	if (type == N3000BMC_SEC)
		sec->image_load = n3000_image_load_hndlrs;
	else if (type == D5005BMC_SEC || type == N5010BMC_SEC)
		sec->image_load = d5005_image_load_hndlrs;
	else if (type == N6000BMC_SEC)
		sec->image_load = pmci_image_load_hndlrs;

	if (type == N6000BMC_SEC)
		sec->poc = &pmci_power_on_image;

	if (type == N6000BMC_SEC && !sec->m10bmc->flash_ops) {
		dev_err(sec->dev, "No flash-ops provided for security manager\n");
		return -EINVAL;
	}

	dev_set_drvdata(&pdev->dev, sec);

	ret = xa_alloc(&fw_upload_xa, &sec->fw_name_id, sec,
		       xa_limit_32b, GFP_KERNEL);
	if (ret)
		return ret;

	len = scnprintf(buf, SEC_UPDATE_LEN_MAX, "secure-update%d",
			sec->fw_name_id);
	sec->fw_name = kmemdup_nul(buf, len, GFP_KERNEL);
	if (!sec->fw_name)
		return -ENOMEM;

	fwl = firmware_upload_register(THIS_MODULE, sec->dev, sec->fw_name,
				       ops, sec);
	if (IS_ERR(fwl)) {
		dev_err(sec->dev, "Firmware Upload driver failed to start\n");
		kfree(sec->fw_name);
		xa_erase(&fw_upload_xa, sec->fw_name_id);
		return PTR_ERR(fwl);
	}

	sec->fwl = fwl;
	return 0;
}

static int m10bmc_sec_remove(struct platform_device *pdev)
{
	struct m10bmc_sec *sec = dev_get_drvdata(&pdev->dev);

	firmware_upload_unregister(sec->fwl);
	kfree(sec->fw_name);
	xa_erase(&fw_upload_xa, sec->fw_name_id);

	return 0;
}

static const struct platform_device_id intel_m10bmc_sec_ids[] = {
	{
		.name = "n3000bmc-sec-update",
		.driver_data = (unsigned long)N3000BMC_SEC,
	},
	{
		.name = "d5005bmc-sec-update",
		.driver_data = (unsigned long)D5005BMC_SEC,
	},
	{
		.name = "n5010bmc-sec-update",
		.driver_data = (unsigned long)N5010BMC_SEC,
	},
	{
		.name = "n6000bmc-sec-update",
		.driver_data = (unsigned long)N6000BMC_SEC,
	},
	{ }
};

static struct platform_driver intel_m10bmc_sec_driver = {
	.probe = m10bmc_sec_probe,
	.remove = m10bmc_sec_remove,
	.driver = {
		.name = "intel-m10bmc-sec-update",
		.dev_groups = m10bmc_sec_attr_groups,
	},
	.id_table = intel_m10bmc_sec_ids,
};
module_platform_driver(intel_m10bmc_sec_driver);

MODULE_DEVICE_TABLE(platform, intel_m10bmc_sec_ids);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Secure Update");
MODULE_LICENSE("GPL");
