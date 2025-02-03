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
#define STAT_END	0x2c
#define MODPRSL         BIT(0)
#define DELAY_REG       0x38
#define DELAY_VALUE       0xffffff

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
#define QSFP_SHADOW_CSRS_BASE_END	0x3fc

#define DELAY_US 1000

#define QSFP_CHECK_TIME 500

enum qsfp_init_status {
	QSFP_INIT_RESET = 0,
	QSFP_INIT_DONE,
};

/**
 * struct qsfp - device private data structure
 * @base: base address of the device.
 * @regmap: regmap for device.
 * @dwork: work struct for checking qsfp plugin status.
 * @dev: point to dfl device.
 * @init: qsfp init status.
 * @lock: lock for qsfp initial function and status.
 */
struct qsfp {
	void __iomem *base;
	struct regmap *regmap;
	struct delayed_work dwork;
	struct device *dev;
	enum qsfp_init_status init;
	struct mutex lock;
};

/* The QSFP controller defines 64-bit wide registers, but support
 * for 64-bit IO in regmap-mmio was removed in upstream commit
 * 159dfabd207628c983e0c3c5ef607f496ff5e6a5. Hence the regmap
 * register ranges are defined in terms of 32-bit wide registers.
 */
static const struct regmap_range qsfp_mem_regmap_range[] = {
	regmap_reg_range(CONF_OFF, STAT_END),
	regmap_reg_range(QSFP_SHADOW_CSRS_BASE_OFF, QSFP_SHADOW_CSRS_BASE_END),
};

static const struct regmap_access_table qsfp_mem_access_table = {
	.yes_ranges	= qsfp_mem_regmap_range,
	.n_yes_ranges	= ARRAY_SIZE(qsfp_mem_regmap_range),
};

static void qsfp_init_i2c(struct qsfp *qsfp)
{
	writel(I2C_ISER_TXRDY | I2C_ISER_RXRDY, qsfp->base + I2C_ISER);
	writel(COUNT_PERIOD_LOW, qsfp->base + I2C_SCL_LOW);
	writel(COUNT_PERIOD_HIGH, qsfp->base + I2C_SCL_HIGH);
	writel(COUNT_PERIOD_HOLD, qsfp->base + I2C_SDA_HOLD);

	writel(FIELD_PREP(I2C_CTRL_FIFO, I2C_CTRL_FIFO_NOT_FULL) |
	       I2C_CTRL_EN | I2C_CTRL_BSP, qsfp->base + I2C_CTRL);
}

static const struct regmap_config mmio_cfg = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.fast_io = true,
	.rd_table = &qsfp_mem_access_table,
	.max_register = QSFP_SHADOW_CSRS_BASE_END,
};

static void qsfp_init(struct qsfp *qsfp)
{
	writeq(CONF_RST_MOD | CONF_RST_CON | CONF_MOD_SEL,
	       qsfp->base + CONF_OFF);
	udelay(DELAY_US);
	writeq(CONF_MOD_SEL, qsfp->base + CONF_OFF);
	udelay(DELAY_US);

	qsfp_init_i2c(qsfp);

	udelay(DELAY_US);
	writeq(DELAY_VALUE, qsfp->base + DELAY_REG);

	writeq(CONF_POLL_EN | CONF_MOD_SEL, qsfp->base + CONF_OFF);
	udelay(DELAY_US);
}

static int check_qsfp_plugin(struct qsfp *qsfp)
{
	u64 status;

	status = readq(qsfp->base + STAT_OFF);

	return (!(status & MODPRSL));
}

static void qsfp_check_hotplug(struct work_struct *work)
{
	struct delayed_work *dwork;
	struct qsfp *qsfp;
	u64 status;

	dwork = to_delayed_work(work);
	qsfp = container_of(dwork, struct qsfp, dwork);

	mutex_lock(&qsfp->lock);

	status = readq(qsfp->base + STAT_OFF);
	dev_dbg(qsfp->dev, "qsfp status 0x%llx\n", status);

	if (check_qsfp_plugin(qsfp) &&
	    qsfp->init == QSFP_INIT_RESET) {
		dev_info(qsfp->dev, "detected QSFP plugin\n");
		qsfp_init(qsfp);
		WRITE_ONCE(qsfp->init, QSFP_INIT_DONE);
	} else if (!check_qsfp_plugin(qsfp) &&
		   qsfp->init == QSFP_INIT_DONE) {
		dev_info(qsfp->dev, "detected QSFP unplugin\n");
		WRITE_ONCE(qsfp->init, QSFP_INIT_RESET);
	}
	mutex_unlock(&qsfp->lock);

	schedule_delayed_work(&qsfp->dwork, msecs_to_jiffies(QSFP_CHECK_TIME));
}

static ssize_t qsfp_connected_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct qsfp *qsfp = dev_get_drvdata(dev);
	u32 plugin;

	mutex_lock(&qsfp->lock);
	plugin = check_qsfp_plugin(qsfp) && (qsfp->init == QSFP_INIT_DONE);
	mutex_unlock(&qsfp->lock);

	return sysfs_emit(buf, "%u\n", plugin);
}

static DEVICE_ATTR_RO(qsfp_connected);

static struct attribute *qsfp_mem_attrs[] = {
	&dev_attr_qsfp_connected.attr,
	NULL,
};
ATTRIBUTE_GROUPS(qsfp_mem);

static int qsfp_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct qsfp *qsfp;

	qsfp = devm_kzalloc(dev, sizeof(*qsfp), GFP_KERNEL);
	if (!qsfp)
		return -ENOMEM;

	qsfp->base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (!qsfp->base)
		return -ENOMEM;

	qsfp->dev = dev;
	mutex_init(&qsfp->lock);

	dev_set_drvdata(dev, qsfp);

	INIT_DELAYED_WORK(&qsfp->dwork, qsfp_check_hotplug);
	qsfp_check_hotplug(&qsfp->dwork.work);

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

	cancel_delayed_work_sync(&qsfp->dwork);
}

#define FME_FEATURE_ID_QSFP 0x13

static const struct dfl_device_id qsfp_ids[] = {
	{ FME_ID, FME_FEATURE_ID_QSFP },
	{ }
};

static struct dfl_driver qsfp_driver = {
	.drv = {
		.name = "qsfp-mem",
		.dev_groups = qsfp_mem_groups,
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
