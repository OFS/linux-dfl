// SPDX-License-Identifier: GPL-2.0
/*
 * Intel MAX 10 Board Management Controller chip
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 */
#include <linux/bitfield.h>
#include <linux/init.h>
#include <linux/mfd/core.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>

enum m10bmc_type {
	M10_N3000,
};

static struct mfd_cell m10bmc_pacn3000_subdevs[] = {
	{ .name = "n3000bmc-hwmon" },
	{ .name = "n3000bmc-retimer" },
	{ .name = "n3000bmc-secure"},
};

static void
m10bmc_init_cells_platdata(struct intel_m10bmc_platdata *pdata,
			   struct mfd_cell *cells, int n_cell)
{
	int i;

	for (i = 0; i < n_cell; i++) {
		if (!strcmp(cells[i].name, "n3000bmc-retimer")) {
			cells[i].platform_data = pdata->retimer;
			cells[i].pdata_size =
				pdata->retimer ? sizeof(*pdata->retimer) : 0;
		}
	}
}

static struct regmap_config intel_m10bmc_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = M10BMC_MEM_END,
};

static ssize_t bmc_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *ddata = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(ddata, M10BMC_BUILD_VER, &val);
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

	ret = m10bmc_sys_read(ddata, NIOS2_FW_VERSION, &val);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}
static DEVICE_ATTR_RO(bmcfw_version);

static ssize_t mac_address_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *max10 = dev_get_drvdata(dev);
	unsigned int macaddr1, macaddr2;
	int ret;

	ret = m10bmc_sys_read(max10, M10BMC_MACADDR1, &macaddr1);
	if (ret)
		return ret;

	ret = m10bmc_sys_read(max10, M10BMC_MACADDR2, &macaddr2);
	if (ret)
		return ret;

	return sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		       (u8)FIELD_GET(M10BMC_MAC_BYTE1, macaddr1),
		       (u8)FIELD_GET(M10BMC_MAC_BYTE2, macaddr1),
		       (u8)FIELD_GET(M10BMC_MAC_BYTE3, macaddr1),
		       (u8)FIELD_GET(M10BMC_MAC_BYTE4, macaddr1),
		       (u8)FIELD_GET(M10BMC_MAC_BYTE5, macaddr2),
		       (u8)FIELD_GET(M10BMC_MAC_BYTE6, macaddr2));
}
static DEVICE_ATTR_RO(mac_address);

static ssize_t mac_count_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *max10 = dev_get_drvdata(dev);
	unsigned int macaddr2;
	int ret;

	ret = m10bmc_sys_read(max10, M10BMC_MACADDR2, &macaddr2);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n",
		       (u8)FIELD_GET(M10BMC_MAC_COUNT, macaddr2));
}
static DEVICE_ATTR_RO(mac_count);

static struct attribute *m10bmc_attrs[] = {
	&dev_attr_bmc_version.attr,
	&dev_attr_bmcfw_version.attr,
	&dev_attr_mac_address.attr,
	&dev_attr_mac_count.attr,
	NULL,
};
ATTRIBUTE_GROUPS(m10bmc);

static int check_m10bmc_version(struct intel_m10bmc *ddata)
{
	unsigned int v;
	int ret;

	ret = m10bmc_raw_read(ddata,
			      M10BMC_LEGACY_SYS_BASE + M10BMC_BUILD_VER, &v);
	if (ret)
		return -ENODEV;

	if (v != 0xffffffff) {
		dev_err(ddata->dev, "bad version M10BMC detected\n");
		return -ENODEV;
	}

	return 0;
}

static int intel_m10_bmc_spi_probe(struct spi_device *spi)
{
	struct intel_m10bmc_platdata *pdata = dev_get_platdata(&spi->dev);
	const struct spi_device_id *id = spi_get_device_id(spi);
	struct device *dev = &spi->dev;
	struct mfd_cell *cells;
	struct intel_m10bmc *ddata;
	int ret, n_cell;

	ddata = devm_kzalloc(dev, sizeof(*ddata), GFP_KERNEL);
	if (!ddata)
		return -ENOMEM;

	ddata->dev = dev;

	ddata->regmap =
		devm_regmap_init_spi_avmm(spi, &intel_m10bmc_regmap_config);
	if (IS_ERR(ddata->regmap)) {
		ret = PTR_ERR(ddata->regmap);
		dev_err(dev, "Failed to allocate regmap: %d\n", ret);
		return ret;
	}

	spi_set_drvdata(spi, ddata);

	ret = check_m10bmc_version(ddata);
	if (ret) {
		dev_err(dev, "Failed to identify m10bmc hardware\n");
		return ret;
	}

	switch (id->driver_data) {
	case M10_N3000:
		cells = m10bmc_pacn3000_subdevs;
		n_cell = ARRAY_SIZE(m10bmc_pacn3000_subdevs);
		break;
	default:
		return -ENODEV;
	}

	m10bmc_init_cells_platdata(pdata, cells, n_cell);

	ret = devm_mfd_add_devices(dev, PLATFORM_DEVID_AUTO, cells, n_cell,
				   NULL, 0, NULL);
	if (ret)
		dev_err(dev, "Failed to register sub-devices: %d\n", ret);

	return ret;
}

static const struct spi_device_id m10bmc_spi_id[] = {
	{ "m10-n3000", M10_N3000 },
	{ }
};
MODULE_DEVICE_TABLE(spi, m10bmc_spi_id);

static struct spi_driver intel_m10bmc_spi_driver = {
	.driver = {
		.name = "intel-m10-bmc",
		.dev_groups = m10bmc_groups,
	},
	.probe = intel_m10_bmc_spi_probe,
	.id_table = m10bmc_spi_id,
};
module_spi_driver(intel_m10bmc_spi_driver);

MODULE_DESCRIPTION("Intel MAX 10 BMC Device Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("spi:intel-m10-bmc");
