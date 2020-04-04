// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller chip Driver
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/bitfield.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/module.h>
#include <linux/mfd/core.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux/mfd/intel-m10-bmc.h>

#include "intel-spi-avmm.h"

enum m10bmc_type {
	M10_N3000,
	M10_D5005
};

static struct mfd_cell m10bmc_bmc_subdevs[] = {
	{
		.name = d5005BMC_HWMON_DEV_NAME,
	},
};

static struct mfd_cell m10bmc_pacn3000_subdevs[] = {
	{
		.name = N3000BMC_HWMON_DEV_NAME,
	}
};

static struct regmap_config intel_m10bmc_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = M10BMC_MEM_END,
};

static ssize_t bmc_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *m10bmc = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(m10bmc, M10BMC_BUILD_VER, &val);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}
static DEVICE_ATTR_RO(bmc_version);

static ssize_t bmcfw_version_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct intel_m10bmc *max10 = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = m10bmc_sys_read(max10, NIOS2_FW_VERSION, &val);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}
static DEVICE_ATTR_RO(bmcfw_version);

static struct attribute *m10bmc_attrs[] = {
	&dev_attr_bmc_version.attr,
	&dev_attr_bmcfw_version.attr,
	NULL,
};

static struct attribute_group m10bmc_attr_group = {
	.attrs = m10bmc_attrs,
};

static const struct attribute_group *m10bmc_dev_groups[] = {
	&m10bmc_attr_group,
	NULL
};

static int check_m10bmc_version(struct intel_m10bmc *m10bmc)
{
	unsigned int v;

	if (m10bmc_raw_read(m10bmc, M10BMC_LEGACY_SYS_BASE + M10BMC_BUILD_VER,
			    &v))
		return -ENODEV;

	if (v != 0xffffffff) {
		dev_err(m10bmc->dev, "bad version M10BMC detected\n");
		return -ENODEV;
	}

	return 0;
}

static int m10bmc_spi_setup(struct spi_device *spi)
{
	/* try 32 bits bpw first then fall back to 8 bits bpw */
	spi->mode = SPI_MODE_1;
	spi->bits_per_word = 32;
	if (!spi_setup(spi))
		return 0;

	spi->bits_per_word = 8;
	return spi_setup(spi);
}

static int intel_m10_bmc_spi_probe(struct spi_device *spi)
{
	const struct spi_device_id *id = spi_get_device_id(spi);
	struct device *dev = &spi->dev;
	struct mfd_cell *cells;
	struct intel_m10bmc *m10bmc;
	int ret, n_cell;

	/* try 32 bits bpw first then fall back to 8 bits bpw */
	ret = m10bmc_spi_setup(spi);
	if (ret)
		return ret;

	m10bmc = devm_kzalloc(dev, sizeof(*m10bmc), GFP_KERNEL);
	if (!m10bmc)
		return -ENOMEM;

	m10bmc->dev = dev;

	m10bmc->regmap =
		devm_regmap_init_spi_avmm(spi, &intel_m10bmc_regmap_config);
	if (IS_ERR(m10bmc->regmap)) {
		ret = PTR_ERR(m10bmc->regmap);
		dev_err(dev, "Failed to allocate regmap: %d\n", ret);
		return ret;
	}

	spi_set_drvdata(spi, m10bmc);

	ret = check_m10bmc_version(m10bmc);
	if (ret) {
		dev_err(dev, "Failed to identify m10bmc hardware\n");
		return ret;
	}

	switch (id->driver_data) {
	case M10_N3000:
		cells = m10bmc_pacn3000_subdevs;
		n_cell = ARRAY_SIZE(m10bmc_pacn3000_subdevs);
		break;
	case M10_D5005:
		cells = m10bmc_bmc_subdevs;
		n_cell = ARRAY_SIZE(m10bmc_bmc_subdevs);
		break;
	default:
		return -ENODEV;
	}

	ret = devm_mfd_add_devices(dev, PLATFORM_DEVID_AUTO, cells, n_cell,
				   NULL, 0, NULL);
	if (ret)
		dev_err(dev, "Failed to register sub-devices: %d\n", ret);

	return ret;
}

static const struct spi_device_id m10bmc_spi_id[] = {
	{ "m10-n3000", M10_N3000 },
	{ "m10-d5005", M10_D5005 },
	{ }
};
MODULE_DEVICE_TABLE(spi, m10bmc_spi_id);

static struct spi_driver intel_m10bmc_spi_driver = {
	.driver = {
		.name = "intel-m10-bmc",
		.dev_groups = m10bmc_dev_groups,
	},
	.probe = intel_m10_bmc_spi_probe,
	.id_table	= m10bmc_spi_id,
};

module_spi_driver(intel_m10bmc_spi_driver);

MODULE_DESCRIPTION("Intel Max10 BMC Device Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("spi:intel-m10-bmc");
