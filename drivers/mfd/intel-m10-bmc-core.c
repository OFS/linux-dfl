// SPDX-License-Identifier: GPL-2.0
/*
 * Intel MAX 10 Board Management Controller chip - common code
 *
 * Copyright (C) 2018-2021 Intel Corporation. All rights reserved.
 */

#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/mfd/core.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>

static struct mfd_cell pmci_bmc_subdevs[] = {
	{ .name = "intel-pmci-hwmon" },
	{ .name = "intel-pmci-secure" },
	{ .name = "intel-pmci-log" }
};

static const struct regmap_range pmci_fw_handshake_regs[] = {
	regmap_reg_range(PMCI_M10BMC_TELEM_START, PMCI_M10BMC_TELEM_END),
};

static const struct m10bmc_csr pmci_m10bmc_csr = {
	.base = PMCI_M10BMC_SYS_BASE,
	.build_version = PMCI_M10BMC_BUILD_VER,
	.fw_version = PMCI_NIOS2_FW_VERSION,
	.mac_low = PMCI_M10BMC_MAC_LOW,
	.mac_high = PMCI_M10BMC_MAC_HIGH,
	.doorbell = PMCI_M10BMC_DOORBELL,
	.auth_result = PMCI_M10BMC_AUTH_RESULT,
};

static const struct m10bmc_csr spi_m10bmc_csr = {
	.base = M10BMC_SYS_BASE,
	.build_version = M10BMC_BUILD_VER,
	.fw_version = NIOS2_FW_VERSION,
	.mac_low = M10BMC_MAC_LOW,
	.mac_high = M10BMC_MAC_HIGH,
	.doorbell = M10BMC_DOORBELL,
	.auth_result = M10BMC_AUTH_RESULT,
};

static struct mfd_cell m10bmc_bmc_subdevs[] = {
	{ .name = "d5005bmc-hwmon" },
	{ .name = "d5005bmc-secure" }
};

static const struct regmap_range d5005_fw_handshake_regs[] = {
	regmap_reg_range(M10BMC_D5005_TELEM_START, M10BMC_D5005_TELEM_END),
};

static struct mfd_cell m10bmc_pacn3000_subdevs[] = {
	{ .name = "n3000bmc-hwmon" },
	{ .name = "n3000bmc-retimer" },
	{ .name = "n3000bmc-secure" },
};

static const struct regmap_range n3000_fw_handshake_regs[] = {
	regmap_reg_range(M10BMC_N3000_TELEM_START, M10BMC_N3000_TELEM_END),
};

static int
m10bmc_flash_read(struct intel_m10bmc *m10bmc, void *buf, u32 addr, u32 size)
{
	unsigned int stride = regmap_get_reg_stride(m10bmc->regmap);
	int ret;

	WARN_ON(size % stride);
	ret = regmap_bulk_read(m10bmc->regmap, addr, buf, size / stride);
	if (ret)
		dev_err(m10bmc->dev,
			"failed to read flash block data: %x cnt %x: %d\n",
			addr, size / stride, ret);
	return ret;
}

static int
m10bmc_pmci_set_flash_host_mux(struct intel_m10bmc *m10bmc, bool request)
{
	u32 ctrl;
	int ret;

	ret = regmap_update_bits(m10bmc->regmap, PMCI_M10BMC_FLASH_CTRL,
				 FLASH_HOST_REQUEST, request);
	if (ret)
		return ret;

	return regmap_read_poll_timeout(m10bmc->regmap,
					PMCI_M10BMC_FLASH_CTRL, ctrl,
					request ? (get_flash_mux(ctrl) == FLASH_MUX_HOST) :
					(get_flash_mux(ctrl) != FLASH_MUX_HOST),
					M10_FLASH_INT_US, M10_FLASH_TIMEOUT_US);
}

static int
m10bmc_pmci_flash_read(struct intel_m10bmc *m10bmc, void *buffer,
		       u32 addr, u32 size)
{
	int ret;

	ret = m10bmc_pmci_set_flash_host_mux(m10bmc, true);
	if (ret)
		return ret;

	ret = m10bmc->flash_ops->read_blk(m10bmc, buffer, addr, size);
	if (ret)
		goto read_fail;

	return m10bmc_pmci_set_flash_host_mux(m10bmc, false);

read_fail:
	m10bmc_pmci_set_flash_host_mux(m10bmc, false);
	return ret;
}

int m10bmc_fw_state_enter(struct intel_m10bmc *m10bmc,
			  enum m10bmc_fw_state new_state)
{
	int ret = 0;

	if (new_state == M10BMC_FW_STATE_NORMAL)
		return -EINVAL;

	down_write(&m10bmc->bmcfw_lock);

	if (m10bmc->bmcfw_state == M10BMC_FW_STATE_NORMAL)
		m10bmc->bmcfw_state = new_state;
	else if (m10bmc->bmcfw_state != new_state)
		ret = -EBUSY;

	up_write(&m10bmc->bmcfw_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(m10bmc_fw_state_enter);

void m10bmc_fw_state_exit(struct intel_m10bmc *m10bmc)
{
	down_write(&m10bmc->bmcfw_lock);

	m10bmc->bmcfw_state = M10BMC_FW_STATE_NORMAL;

	up_write(&m10bmc->bmcfw_lock);
}
EXPORT_SYMBOL_GPL(m10bmc_fw_state_exit);

static bool is_handshake_sys_reg(struct intel_m10bmc *m10bmc,
				 unsigned int offset)
{
	return regmap_reg_in_ranges(offset, m10bmc->handshake_sys_reg_ranges,
				    m10bmc->handshake_sys_reg_nranges);
}

int m10bmc_sys_read(struct intel_m10bmc *m10bmc, unsigned int offset,
		    unsigned int *val)
{
	int ret;

	if (!is_handshake_sys_reg(m10bmc, offset))
		return m10bmc_raw_read(m10bmc, m10bmc->csr->base + (offset), val);

	down_read(&m10bmc->bmcfw_lock);

	if (m10bmc->bmcfw_state == M10BMC_FW_STATE_SEC_UPDATE)
		ret = -EBUSY;
	else
		ret = m10bmc_raw_read(m10bmc, m10bmc->csr->base + (offset), val);

	up_read(&m10bmc->bmcfw_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(m10bmc_sys_read);

int m10bmc_sys_update_bits(struct intel_m10bmc *m10bmc, unsigned int offset,
			   unsigned int msk, unsigned int val)
{
	int ret;

	if (!is_handshake_sys_reg(m10bmc, offset))
		return regmap_update_bits(m10bmc->regmap,
					  m10bmc->csr->base + (offset), msk, val);

	down_read(&m10bmc->bmcfw_lock);

	if (m10bmc->bmcfw_state == M10BMC_FW_STATE_SEC_UPDATE)
		ret = -EBUSY;
	else
		ret = regmap_update_bits(m10bmc->regmap,
					 m10bmc->csr->base + (offset), msk, val);

	up_read(&m10bmc->bmcfw_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(m10bmc_sys_update_bits);

static ssize_t bmc_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *ddata = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(ddata, ddata->csr->build_version, &val);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}
static DEVICE_ATTR_RO(bmc_version);

static ssize_t bmcfw_version_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *ddata = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(ddata, ddata->csr->fw_version, &val);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}
static DEVICE_ATTR_RO(bmcfw_version);

static ssize_t mac_address_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *ddata = dev_get_drvdata(dev);
	unsigned int macaddr_low, macaddr_high;
	int ret;

	ret = m10bmc_sys_read(ddata, ddata->csr->mac_low, &macaddr_low);
	if (ret)
		return ret;

	ret = m10bmc_sys_read(ddata, ddata->csr->mac_high, &macaddr_high);
	if (ret)
		return ret;

	return sysfs_emit(buf, "%02x:%02x:%02x:%02x:%02x:%02x\n",
			  (u8)FIELD_GET(M10BMC_MAC_BYTE1, macaddr_low),
			  (u8)FIELD_GET(M10BMC_MAC_BYTE2, macaddr_low),
			  (u8)FIELD_GET(M10BMC_MAC_BYTE3, macaddr_low),
			  (u8)FIELD_GET(M10BMC_MAC_BYTE4, macaddr_low),
			  (u8)FIELD_GET(M10BMC_MAC_BYTE5, macaddr_high),
			  (u8)FIELD_GET(M10BMC_MAC_BYTE6, macaddr_high));
}
static DEVICE_ATTR_RO(mac_address);

static ssize_t mac_count_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *ddata = dev_get_drvdata(dev);
	unsigned int macaddr_high;
	int ret;

	ret = m10bmc_sys_read(ddata, ddata->csr->mac_high, &macaddr_high);
	if (ret)
		return ret;

	return sysfs_emit(buf, "%u\n",
			  (u8)FIELD_GET(M10BMC_MAC_COUNT, macaddr_high));
}
static DEVICE_ATTR_RO(mac_count);

static struct attribute *m10bmc_attrs[] = {
	&dev_attr_bmc_version.attr,
	&dev_attr_bmcfw_version.attr,
	&dev_attr_mac_address.attr,
	&dev_attr_mac_count.attr,
	NULL,
};

static const struct attribute_group m10bmc_group = {
	.attrs = m10bmc_attrs,
};

const struct attribute_group *m10bmc_dev_groups[] = {
	&m10bmc_group,
	NULL,
};
EXPORT_SYMBOL_GPL(m10bmc_dev_groups);

static int check_m10bmc_version(struct intel_m10bmc *ddata)
{
	unsigned int v;
	int ret;

	/*
	 * This check is to filter out the very old legacy BMC versions,
	 * 0x300400 is the offset to this old block of mmio registers. In the
	 * old BMC chips, the BMC version info is stored in this old version
	 * register (0x300400 + 0x68), so its read out value would have not
	 * been LEGACY_INVALID (0xffffffff). But in new BMC chips that the
	 * driver supports, the value of this register should be
	 * LEGACY_INVALID.
	 */
	ret = m10bmc_raw_read(ddata, M10BMC_LEGACY_BUILD_VER, &v);
	if (ret)
		return -ENODEV;

	if (v != M10BMC_VER_LEGACY_INVALID) {
		dev_err(ddata->dev, "bad version M10BMC detected\n");
		return -ENODEV;
	}

	return 0;
}

int m10bmc_dev_init(struct intel_m10bmc *m10bmc)
{
	enum m10bmc_type type = m10bmc->type;
	struct mfd_cell *cells;
	int ret, n_cell;

	init_rwsem(&m10bmc->bmcfw_lock);
	dev_set_drvdata(m10bmc->dev, m10bmc);

	if (m10bmc->type == M10_PMCI) {
		if (!m10bmc->flash_ops) {
			dev_err(m10bmc->dev,
				"No flash-ops provided\n");
			return -EINVAL;
		}
		m10bmc->ops.flash_read = m10bmc_pmci_flash_read;
	} else {
		ret = check_m10bmc_version(m10bmc);
		if (ret) {
			dev_err(m10bmc->dev, "Failed to identify m10bmc hardware\n");
			return ret;
		}
		m10bmc->ops.flash_read = m10bmc_flash_read;
	}

	switch (type) {
	case M10_N3000:
		cells = m10bmc_pacn3000_subdevs;
		n_cell = ARRAY_SIZE(m10bmc_pacn3000_subdevs);
		m10bmc->handshake_sys_reg_ranges = n3000_fw_handshake_regs;
		m10bmc->handshake_sys_reg_nranges =
			ARRAY_SIZE(n3000_fw_handshake_regs);
		m10bmc->csr = &spi_m10bmc_csr;
		break;
	case M10_D5005:
		cells = m10bmc_bmc_subdevs;
		n_cell = ARRAY_SIZE(m10bmc_bmc_subdevs);
		m10bmc->handshake_sys_reg_ranges = d5005_fw_handshake_regs;
		m10bmc->handshake_sys_reg_nranges =
			ARRAY_SIZE(d5005_fw_handshake_regs);
		m10bmc->csr = &spi_m10bmc_csr;
		break;
	case M10_PMCI:
		cells = pmci_bmc_subdevs;
		n_cell = ARRAY_SIZE(pmci_bmc_subdevs);
		m10bmc->handshake_sys_reg_ranges = pmci_fw_handshake_regs;
		m10bmc->handshake_sys_reg_nranges =
			ARRAY_SIZE(pmci_fw_handshake_regs);
		m10bmc->csr = &pmci_m10bmc_csr;
		break;
	default:
		return -ENODEV;
	}

	ret = devm_mfd_add_devices(m10bmc->dev, PLATFORM_DEVID_AUTO,
				   cells, n_cell, NULL, 0, NULL);
	if (ret)
		dev_err(m10bmc->dev, "Failed to register sub-devices: %d\n",
			ret);

	return ret;
}
EXPORT_SYMBOL_GPL(m10bmc_dev_init);

MODULE_DESCRIPTION("Intel MAX 10 BMC core MFD driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
