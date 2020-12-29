// SPDX-License-Identifier: GPL-2.0

/* Intel(R) Memory based QSFP driver.
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 */

#include <linux/bitfield.h>
#include <linux/dfl.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/i2c.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/regmap.h>
#include <linux/uaccess.h>

#define CONF_OFF	0x20
#define CONF_RST_MOD	BIT(0)
#define CONF_RST_CON	BIT(1)
#define CONF_MOD_SEL	BIT(2)
#define CONF_LOW_POW	BIT(3)
#define CONF_POLL_EN	BIT(4)

#define STAT_OFF	0x28

#define I2C_CTRL        0x48
#define I2C_CTRL_EN	BIT(0)
#define I2C_CTRL_BSP	BIT(1)
#define I2C_CTRL_FIFO  GENMASK(3, 2)
#define I2C_CTRL_FIFO_NOT_FULL 3

#define I2C_ISER	0x4c
#define I2C_ISER_TXRDY	BIT(0)
#define I2C_ISER_RXRDY	BIT(1)
#define I2C_SCL_LOW	0x60
#define COUNT_PERIOD_LOW 0x82
#define I2C_SCL_HIGH	0x64
#define COUNT_PERIOD_HIGH 0x3c
#define I2C_SDA_HOLD	0x68
#define COUNT_PERIOD_HOLD 0x28

#define QSFP_SHADOW_CSRS_BASE_OFF	0x100
#define QSFP_SHADOW_CSRS_BASE_END	0x3f8

#define DELAY_US 1000

struct qsfp {
	void __iomem *base;
	struct regmap *regmap;
};

static const struct regmap_range qsfp_mem_regmap_range[] = {
	regmap_reg_range(CONF_OFF, STAT_OFF),
	regmap_reg_range(QSFP_SHADOW_CSRS_BASE_OFF, QSFP_SHADOW_CSRS_BASE_END),
};

static const struct regmap_access_table qsfp_mem_access_table = {
	.yes_ranges	= qsfp_mem_regmap_range,
	.n_yes_ranges	= ARRAY_SIZE(qsfp_mem_regmap_range),
};

static void qsfp_init_i2c(struct device *dev, struct qsfp *qsfp)
{
	writel(I2C_ISER_TXRDY | I2C_ISER_RXRDY, qsfp->base + I2C_ISER);
	writel(COUNT_PERIOD_LOW, qsfp->base + I2C_SCL_LOW);
	writel(COUNT_PERIOD_HIGH, qsfp->base + I2C_SCL_HIGH);
	writel(COUNT_PERIOD_HOLD, qsfp->base + I2C_SDA_HOLD);

	writel(FIELD_PREP(I2C_CTRL_FIFO, I2C_CTRL_FIFO_NOT_FULL) |
	       I2C_CTRL_EN | I2C_CTRL_BSP, qsfp->base + I2C_CTRL);
}

static const struct regmap_config mmio_cfg = {
	.reg_bits = 64,
	.reg_stride = 8,
	.val_bits = 64,
	.fast_io = true,
	.rd_table = &qsfp_mem_access_table,
	.max_register = QSFP_SHADOW_CSRS_BASE_END,
};

static int qsfp_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct qsfp *qsfp;

	qsfp = devm_kzalloc(dev, sizeof(*qsfp), GFP_KERNEL);
	if (!qsfp)
		return -ENOMEM;

	dev_set_drvdata(dev, qsfp);

	qsfp->base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (!qsfp->base)
		return -ENOMEM;

	writeq(CONF_RST_MOD | CONF_RST_CON | CONF_MOD_SEL,
	       qsfp->base + CONF_OFF);
	udelay(DELAY_US);
	writeq(CONF_MOD_SEL, qsfp->base + CONF_OFF);
	udelay(DELAY_US);

	qsfp_init_i2c(dev, qsfp);

	writeq(CONF_POLL_EN | CONF_MOD_SEL, qsfp->base + CONF_OFF);
	udelay(DELAY_US);

	qsfp->regmap = devm_regmap_init_mmio(dev, qsfp->base, &mmio_cfg);
	if (IS_ERR(qsfp->regmap))
		dev_err(dev, "Failed to create qsfp regmap\n");

	return PTR_ERR_OR_ZERO(qsfp->regmap);
}

static void qsfp_remove(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct qsfp *qsfp = dev_get_drvdata(dev);

	writeq(CONF_MOD_SEL, qsfp->base + CONF_OFF);
}

#define FME_FEATURE_ID_QSFP 0x13

static const struct dfl_device_id qsfp_ids[] = {
	{ FME_ID, FME_FEATURE_ID_QSFP },
	{ }
};

static struct dfl_driver qsfp_driver = {
	.drv = {
		.name = "qsfp-mem",
	},
	.id_table = qsfp_ids,
	.probe = qsfp_probe,
	.remove = qsfp_remove,
};

module_dfl_driver(qsfp_driver);
MODULE_DEVICE_TABLE(dfl, qsfp_ids);
MODULE_DESCRIPTION("Intel(R) Memory based QSFP driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
