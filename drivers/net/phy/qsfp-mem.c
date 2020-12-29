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
#define STAT_MOD_PRES	BIT(0)
#define STAT_INT_MOD	BIT(1)
#define STAT_INT_I2C	BIT(2)
#define STAT_TX_ERR	BIT(3)
#define STAT_RX_ERR	BIT(4)
#define STAT_SNK_RDY	BIT(5)
#define STAT_SRC_RDY	BIT(6)
#define STAT_FSM_PAUSE	BIT(7)
#define STAT_CURR_PAGE	GENMASK_ULL(15, 8)
#define STAT_CURR_ADDR	GENMASK_ULL(23, 16)

#define I2C_BASE_OFF	0x40
#define I2C_TFR_CMD	I2C_BASE_OFF
#define I2C_RX_DATA	(I2C_BASE_OFF + 0x8)
#define I2C_CTRL	(I2C_BASE_OFF + 0x10)
#define I2C_CTRL_EN	BIT(0)
#define I2C_CTRL_BSP	BIT(1)
#define I2C_CTRL_TCT	GENMASK_ULL(3, 2)
#define I2C_CTRL_RXT	GENMASK_ULL(5, 4)

#define I2C_ISER	(I2C_BASE_OFF + 0x18)
#define I2C_ISER_TXRDY	BIT(0)
#define I2C_ISER_RXRDY	BIT(1)
#define I2C_ISR		(I2C_BASE_OFF + 0x20)
#define I2C_STAT	(I2C_BASE_OFF + 0x28)
#define I2C_TC_FIFO_LVL	(I2C_BASE_OFF + 0x30)
#define I2C_RX_FIFO_LVL	(I2C_BASE_OFF + 0x38)
#define I2C_SCL_LOW	(I2C_BASE_OFF + 0x40)
#define I2C_SCL_HIGH	(I2C_BASE_OFF + 0x48)
#define I2C_SDA_HOLD	(I2C_BASE_OFF + 0x50)

#define QSFP_SHADOW_CSRS_BASE_OFF	0x100

#define POLL_INTERVAL_US 1
#define POLL_TIMEOUT_US 100000

#define RESET_DELAY_US 10

#define INPUT_CLK_FREQ_HZ	100000000
#define BUS_CLK_FREQ_HZ		I2C_MAX_STANDARD_MODE_FREQ

struct qsfp {
	void __iomem *base;
	struct regmap *regmap;
};

static int qsfp_init_mod(struct device *dev, struct qsfp *qsfp)
{
	u64 reg_val;
	int ret;

	reg_val = readq(qsfp->base + STAT_OFF);
	if (!(reg_val & STAT_MOD_PRES)) {
		dev_err(dev, "No QSFP module present.");
		return -ENODEV;
	}

	reg_val = readq(qsfp->base + CONF_OFF);
	if (reg_val & CONF_POLL_EN) {
		reg_val &= ~CONF_POLL_EN;
		writeq(reg_val, qsfp->base + CONF_OFF);

		ret = readq_poll_timeout((qsfp->base + STAT_OFF), reg_val,
					 (reg_val & STAT_FSM_PAUSE),
					 POLL_INTERVAL_US, POLL_TIMEOUT_US);
		if (ret)
			dev_warn(dev, "Timed out waiting for fsm pause.");
	}

	writeq(CONF_RST_MOD | CONF_RST_CON, qsfp->base + CONF_OFF);

	udelay(RESET_DELAY_US);

	writeq(0, qsfp->base + CONF_OFF);

	udelay(RESET_DELAY_US);

	writeq(CONF_MOD_SEL, qsfp->base + CONF_OFF);

	return 0;
}

static void qsfp_init_i2c(struct device *dev, struct qsfp *qsfp)
{
	u64 divisor = INPUT_CLK_FREQ_HZ / I2C_MAX_STANDARD_MODE_FREQ;
	u64 clk_mhz = INPUT_CLK_FREQ_HZ / 1000000;
	u64 reg_val = FIELD_PREP(I2C_CTRL_TCT, 0x2) | FIELD_PREP(I2C_CTRL_RXT, 0x2);
	u64 t_high, t_low;

	if (BUS_CLK_FREQ_HZ <= I2C_MAX_STANDARD_MODE_FREQ) {
		t_high = divisor * 1 / 2;
		t_low = divisor * 1 / 2;
	} else {
		reg_val |= I2C_CTRL_BSP;
		t_high = divisor * 1 / 3;
		t_low = divisor * 2 / 3;
	}

	writeq(reg_val, qsfp->base + I2C_CTRL);

	reg_val = readq(qsfp->base + I2C_CTRL);

	reg_val |= I2C_CTRL_EN;

	writeq(reg_val, qsfp->base + I2C_CTRL);

	writeq(t_high, qsfp->base + I2C_SCL_HIGH);
	writeq(t_low, qsfp->base + I2C_SCL_LOW);
	/* SDA Hold Time, 300ns */
	writeq(3 * clk_mhz / 10, qsfp->base + I2C_SDA_HOLD);

	writeq(I2C_ISER_TXRDY | I2C_CTRL_RXT, qsfp->base + I2C_ISER);
}

static const struct regmap_config mmio_cfg = {
	.reg_bits = 64,
	.reg_stride = 8,
	.val_bits = 64,
	.fast_io = true,
	.max_register = 0x100 + (128 * 6),
};

static int qsfp_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct qsfp *qsfp;
	u64 reg_val;
	int ret;

	qsfp = devm_kzalloc(dev, sizeof(*qsfp), GFP_KERNEL);
	if (!qsfp)
		return -ENOMEM;

	dev_set_drvdata(dev, qsfp);

	qsfp->base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (!qsfp->base)
		return -ENOMEM;

	ret = qsfp_init_mod(dev, qsfp);
	if (ret)
		return ret;

	qsfp_init_i2c(dev, qsfp);

	reg_val = readq(qsfp->base + CONF_OFF);
	reg_val |= CONF_POLL_EN;
	writeq(reg_val, qsfp->base + CONF_OFF);

	qsfp->regmap = devm_regmap_init_mmio(dev, qsfp->base, &mmio_cfg);
	if (IS_ERR(qsfp->regmap))
		dev_err(dev, "Failed to create qsfp regmap\n");

	return PTR_ERR_OR_ZERO(qsfp->regmap);
}

static void qsfp_remove(struct dfl_device *dfl_dev)
{
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
