// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Stratix 10 HSSI Phy
 *
 * Copyright 2019-2020 Intel Corporation, Inc.
 */

#include <linux/bitfield.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/phy/intel-s10-phy.h>
#include <linux/platform_device.h>

/* HSSI QSFP Control & Status Registers */
#define HSSI_QSFP_RCFG_CMD(phy)		((phy)->phy_offset + 0x0)
#define   QSFP_RCFG_CMD			GENMASK_ULL(1, 0)
#define     QSFP_RCFG_CMD_CLR		0
#define     QSFP_RCFG_CMD_RD		1
#define     QSFP_RCFG_CMD_WRT		2
#define   QSFP_RCFG_CMD_SEL_XCVR	GENMASK_ULL(5, 4)   /* XCVR 0 - 3 */
#define   QSFP_RCFG_XCVR_ADDR		GENMASK_ULL(26, 16)
#define   QSFP_RCFG_XCVR_ACK		BIT_ULL(32)

#define HSSI_QSFP_RCFG_DATA(phy)	((phy)->phy_offset + 0x8)
#define   XCVR_RCFG_RDATA		GENMASK_ULL(31, 0)  /* RO: rd data */
#define   XCVR_RCFG_WDATA		GENMASK_ULL(63, 32) /* RW: wrt data */

#define HSSI_QSFP_CTRL(phy)		((phy)->phy_offset + 0x10)
#define   DATA_RATE_SEL_1G		BIT_ULL(0)	/* 1 = Selected */
#define   DATA_RATE_SEL_10G		BIT_ULL(1)
#define   DATA_RATE_SEL_25G		BIT_ULL(2)
#define   DATA_RATE_SEL_40G		BIT_ULL(3)
#define   DATA_RATE_SEL_50G		BIT_ULL(4)
#define   DATA_RATE_SEL_100G		BIT_ULL(5)
#define   DATA_RATE_SEL_200G		BIT_ULL(6)
#define   DATA_RATE_SEL_400G		BIT_ULL(7)
#define   GLOBAL_RESET			BIT_ULL(8)	/* 1 = Active */
#define   RECONFIG_RESET		BIT_ULL(9)
#define   CHAN0_RESET			BIT_ULL(10)
#define   CHAN1_RESET			BIT_ULL(11)
#define   CHAN2_RESET			BIT_ULL(12)
#define   CHAN3_RESET			BIT_ULL(13)
#define   SELECT_ATX_PLL		BIT_ULL(14)	/* 0 = 10G, 1 = 25G */
#define   SELECT_TX_CORE_CLK		BIT_ULL(15)	/* 0 = PHY, 1 = IOPLL */
#define   SELECT_RX_CORE_CLK		BIT_ULL(16)	/* 0 = PHY, 1 = IOPLL */

#define HSSI_QSFP_STAT(phy)		((phy)->phy_offset + 0x18)
#define   HSSI_QSFP_STAT_CHAN0		GENMASK_ULL(15, 0)
#define   HSSI_QSFP_STAT_CHAN1		GENMASK_ULL(31, 16)
#define   HSSI_QSFP_STAT_CHAN2		GENMASK_ULL(47, 32)
#define   HSSI_QSFP_STAT_CHAN3		GENMASK_ULL(63, 48)
#define     TX_ANALOG_RST_STAT		BIT_ULL(0)
#define     TX_DIG_RST_STAT		BIT_ULL(1)
#define     RX_ANALOG_RST_STAT		BIT_ULL(2)
#define     RX_DIG_RST_STAT		BIT_ULL(3)
#define     TX_DIG_RST_TIMEOUT		BIT_ULL(4)
#define     RX_DIG_RST_TIMEOUT		BIT_ULL(5)
#define     TX_FIFO_READY		BIT_ULL(6)
#define     RX_FIFO_READY		BIT_ULL(7)
#define     TX_XFER_READY		BIT_ULL(8)
#define     RX_XFER_READY		BIT_ULL(9)
#define     TX_CAL_BUSY			BIT_ULL(10)
#define     RX_CAL_BUSY			BIT_ULL(11)
#define     RX_LOCKED_TO_DATA		BIT_ULL(12)
#define     RX_LOCKED_TO_REF		BIT_ULL(13)
#define     TX_READY			BIT_ULL(14)
#define     RX_READY			BIT_ULL(15)

#define HSSI_WRITE_POLL_INVL_US		10	/* Write poll interval */
#define HSSI_WRITE_POLL_TIMEOUT_US	100000	/* Write poll timeout */

/* Analog preemphasis tuning parameters */
#define PRE_TAP_ADDR			0x107
#define PRE_TAP_MAGNITUDE_MASK		GENMASK(4, 0)
#define PRE_TAP_MAX			15
#define PRE_TAP_POLARITY		BIT(5)	/* 1 = negative polarity */

#define POST_TAP_ADDR			0x105
#define POST_TAP_MAGNITUDE_MASK		GENMASK(4, 0)
#define POST_TAP_MAX			24
#define POST_TAP_POLARITY		BIT(6)	/* 1 = negative polarity */

#define VOD_COMP_ADDR			0x109
#define VOD_MASK			GENMASK(4, 0)
#define VOD_MIN				17
#define VOD_MAX				31

#define COMPENSATION_FLAG		BIT(5)	/* 1 = ON; 0 = OFF */

struct hssi_phy {
	void __iomem *csr_base;
	u32 phy_offset;
	struct device *dev;
	struct mutex lock;	/* serialize access to phy registers */
};

static int hssi_await_ack(struct hssi_phy *phy)
{
	int ret;
	u64 v;

	/* Poll for the expected state of acknowlege bit */
	ret = readq_poll_timeout(phy->csr_base + HSSI_QSFP_RCFG_CMD(phy), v,
				 v & QSFP_RCFG_XCVR_ACK,
				 HSSI_WRITE_POLL_INVL_US,
				 HSSI_WRITE_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(phy->dev, "timeout, phy ack not received\n");
		return ret;
	}

	/* Clear ACK state */
	v = readq(phy->csr_base + HSSI_QSFP_RCFG_CMD(phy));
	v &= ~QSFP_RCFG_CMD;
	v |= FIELD_PREP(QSFP_RCFG_CMD, QSFP_RCFG_CMD_CLR);
	writeq(v, phy->csr_base + HSSI_QSFP_RCFG_CMD(phy));

	return 0;
}

static int hssi_xcvr_read(struct hssi_phy *phy, u8 chan_num,
			  u16 addr, u32 *data)
{
	int ret;
	u64 v;

	/* Read the desired address */
	v = FIELD_PREP(QSFP_RCFG_CMD, QSFP_RCFG_CMD_RD);
	v |= FIELD_PREP(QSFP_RCFG_CMD_SEL_XCVR, chan_num);
	v |= FIELD_PREP(QSFP_RCFG_XCVR_ADDR, addr);
	writeq(v, phy->csr_base + HSSI_QSFP_RCFG_CMD(phy));

	/* Poll for read complete */
	ret = hssi_await_ack(phy);
	if (ret)
		return ret;

	/* Return data */
	v = readq(phy->csr_base + HSSI_QSFP_RCFG_DATA(phy));
	*data = FIELD_GET(XCVR_RCFG_RDATA, v);

	return 0;
}

static int hssi_xcvr_write(struct hssi_phy *phy, u8 chan_num,
			   u16 addr, u32 data)
{
	u64 v;

	/* Set up the write data */
	v = FIELD_PREP(XCVR_RCFG_WDATA, data);
	writeq(v, phy->csr_base + HSSI_QSFP_RCFG_DATA(phy));

	/* Trigger the write */
	v = FIELD_PREP(QSFP_RCFG_CMD, QSFP_RCFG_CMD_WRT);
	v |= FIELD_PREP(QSFP_RCFG_CMD_SEL_XCVR, chan_num);
	v |= FIELD_PREP(QSFP_RCFG_XCVR_ADDR, addr);
	writeq(v, phy->csr_base + HSSI_QSFP_RCFG_CMD(phy));

	/* Poll for write complete */
	return hssi_await_ack(phy);
}

static int hssi_xcvr_rmw(struct hssi_phy *phy, u8 chan_num,
			 u16 addr, u32 mask, u32 data)
{
	u32 value;
	int ret;

	ret = hssi_xcvr_read(phy, chan_num, addr, &value);
	if (ret)
		return ret;

	value &= ~mask;
	value |= (data & mask);

	return hssi_xcvr_write(phy, chan_num, addr, value);
}

static ssize_t tx_pre_tap_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	u8 magnitude, polarity = 0;
	const char *p = buf;
	unsigned long chan;
	int ret;

	if ((buf[0] == '+') || (buf[0] == '-')) {
		if (buf[0] == '-')
			polarity = PRE_TAP_POLARITY;
		p++;
	}

	ret = kstrtou8(p, 0, &magnitude);
	if (ret)
		return ret;

	if (magnitude > PRE_TAP_MAX) {
		dev_err(phy->dev, "Max pre-tap is %d\n", PRE_TAP_MAX);
		return -EINVAL;
	}

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_rmw(phy, (u8)chan, PRE_TAP_ADDR,
			    PRE_TAP_POLARITY | PRE_TAP_MAGNITUDE_MASK,
			    polarity | magnitude);
	mutex_unlock(&phy->lock);

	return ret ? : count;
}

static ssize_t tx_pre_tap_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	char polarity = '\0';
	unsigned long chan;
	u8 magnitude;
	u32 pre_tap;
	int ret;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_read(phy, (u8)chan, PRE_TAP_ADDR, &pre_tap);
	mutex_unlock(&phy->lock);

	if (ret)
		return ret;

	magnitude = pre_tap & PRE_TAP_MAGNITUDE_MASK;
	if (magnitude)
		polarity = pre_tap & PRE_TAP_POLARITY ? '-' : '+';

	return scnprintf(buf, PAGE_SIZE, "%c%u\n", polarity, magnitude);
}

static ssize_t tx_post_tap_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	u8 magnitude, polarity = 0;
	const char *p = buf;
	unsigned long chan;
	int ret;

	if ((buf[0] == '+') || (buf[0] == '-')) {
		if (buf[0] == '-')
			polarity = POST_TAP_POLARITY;
		p++;
	}

	ret = kstrtou8(p, 0, &magnitude);
	if (ret)
		return ret;

	if (magnitude > POST_TAP_MAX) {
		dev_err(phy->dev, "Max post-tap is %d\n", POST_TAP_MAX);
		return -EINVAL;
	}

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_rmw(phy, (u8)chan, POST_TAP_ADDR,
			    POST_TAP_POLARITY | POST_TAP_MAGNITUDE_MASK,
			    polarity | magnitude);
	mutex_unlock(&phy->lock);

	return ret ? : count;
}

static ssize_t tx_post_tap_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	char polarity = '\0';
	unsigned long chan;
	u8 magnitude;
	u32 post_tap;
	int ret;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_read(phy, (u8)chan, POST_TAP_ADDR, &post_tap);
	mutex_unlock(&phy->lock);

	if (ret)
		return ret;

	magnitude = post_tap & POST_TAP_MAGNITUDE_MASK;
	if (magnitude)
		polarity = post_tap & POST_TAP_POLARITY ? '-' : '+';

	return scnprintf(buf, PAGE_SIZE, "%c%u\n", polarity, magnitude);
}

static ssize_t tx_vod_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	unsigned long chan;
	int ret;
	u8 vod;

	ret = kstrtou8(buf, 0, &vod);
	if (ret)
		return ret;

	if (vod > VOD_MAX || vod < VOD_MIN) {
		dev_err(phy->dev, "Valid VOD range is %d to %d\n",
			VOD_MIN, VOD_MAX);
		return -EINVAL;
	}

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_rmw(phy, (u8)chan, VOD_COMP_ADDR, VOD_MASK, vod);
	mutex_unlock(&phy->lock);

	return ret ? : count;
}

static ssize_t tx_vod_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	unsigned long chan;
	int ret;
	u32 vod;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_read(phy, (u8)chan, VOD_COMP_ADDR, &vod);
	mutex_unlock(&phy->lock);

	return ret ? : scnprintf(buf, PAGE_SIZE, "%lu\n", vod & VOD_MASK);
}

static ssize_t tx_comp_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	unsigned long chan;
	u8 compensation;
	int ret;

	ret = kstrtou8(buf, 0, &compensation);
	if (ret)
		return ret;

	if (compensation > 1) {
		dev_err(phy->dev, "Compensation must be 1 or 0");
		return -EINVAL;
	}

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_rmw(phy, (u8)chan, VOD_COMP_ADDR, COMPENSATION_FLAG,
			    compensation ? COMPENSATION_FLAG : 0);
	mutex_unlock(&phy->lock);

	return ret ? : count;
}

static ssize_t tx_comp_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	struct dev_ext_attribute *eattr;
	unsigned long chan;
	u32 compensation;
	int ret;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	chan = (unsigned long)eattr->var;

	mutex_lock(&phy->lock);
	ret = hssi_xcvr_read(phy, (u8)chan, VOD_COMP_ADDR, &compensation);
	mutex_unlock(&phy->lock);

	return ret ? : scnprintf(buf, PAGE_SIZE, "%u\n",
			 compensation & COMPENSATION_FLAG ? 1 : 0);
}

#define PHY_TUNE_ATTR(_name, _chan)				\
static struct dev_ext_attribute phy_tune_##_name##_chan = {	\
	.attr = __ATTR_RW(_name),				\
	.var = (void *)_chan,					\
}

#define PHY_TUNE_ATTRS(_chan)					\
PHY_TUNE_ATTR(tx_comp, _chan);					\
PHY_TUNE_ATTR(tx_post_tap, _chan);				\
PHY_TUNE_ATTR(tx_pre_tap, _chan);				\
PHY_TUNE_ATTR(tx_vod, _chan);					\
static struct attribute *chan##_chan##_attrs[] = {		\
	&phy_tune_tx_pre_tap##_chan.attr.attr,		\
	&phy_tune_tx_post_tap##_chan.attr.attr,		\
	&phy_tune_tx_vod##_chan.attr.attr,		\
	&phy_tune_tx_comp##_chan.attr.attr,		\
	NULL,							\
};								\
static struct attribute_group chan##_chan##_attr_group = {	\
	.name = __stringify(chan##_chan),			\
	.attrs = chan##_chan##_attrs,				\
}

PHY_TUNE_ATTRS(0);
PHY_TUNE_ATTRS(1);
PHY_TUNE_ATTRS(2);
PHY_TUNE_ATTRS(3);

static ssize_t ctrl_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	int ret;
	u64 v;

	ret = kstrtou64(buf, 0, &v);
	if (ret)
		return ret;

	mutex_lock(&phy->lock);
	writeq(v, phy->csr_base + HSSI_QSFP_CTRL(phy));
	mutex_unlock(&phy->lock);

	return count;
}

static ssize_t ctrl_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	u64 v;

	mutex_lock(&phy->lock);
	v = readq(phy->csr_base + HSSI_QSFP_CTRL(phy));
	mutex_unlock(&phy->lock);

	return scnprintf(buf, PAGE_SIZE, "0x%016llx\n", v);
}
static DEVICE_ATTR_RW(ctrl);

static ssize_t stat_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct hssi_phy *phy = dev_get_drvdata(dev);
	u64 v;

	mutex_lock(&phy->lock);
	v = readq(phy->csr_base + HSSI_QSFP_STAT(phy));
	mutex_unlock(&phy->lock);

	return scnprintf(buf, PAGE_SIZE, "0x%016llx\n", v);
}
static DEVICE_ATTR_RO(stat);

static struct attribute *qsfp_attrs[] = {
	&dev_attr_ctrl.attr,
	&dev_attr_stat.attr,
	NULL,
};

static struct attribute_group qsfp_attr_group = {
	.attrs = qsfp_attrs,
};

static const struct attribute_group *qsfp_attr_groups[] = {
	&qsfp_attr_group,
	&chan0_attr_group,
	&chan1_attr_group,
	&chan2_attr_group,
	&chan3_attr_group,
	NULL,
};

static int intel_s10_phy_probe(struct platform_device *pdev)
{
	struct intel_s10_platform_data *pdata;
	struct device *dev = &pdev->dev;
	struct hssi_phy *phy;

	pdata = dev_get_platdata(dev);
	if (!pdata)
		return -ENODEV;

	phy = devm_kzalloc(dev, sizeof(*phy), GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	phy->csr_base = pdata->csr_base;
	phy->phy_offset = pdata->phy_offset;
	phy->dev = dev;
	mutex_init(&phy->lock);
	dev_set_drvdata(dev, phy);

	return 0;
}

static int intel_s10_phy_remove(struct platform_device *pdev)
{
	struct hssi_phy *phy = dev_get_drvdata(&pdev->dev);

	mutex_destroy(&phy->lock);
	return 0;
}

static struct platform_driver intel_s10_phy_driver = {
	.driver = {
		.name = INTEL_S10_PHY_DRV_NAME,
		.dev_groups = qsfp_attr_groups,
	},
	.probe = intel_s10_phy_probe,
	.remove = intel_s10_phy_remove,
};

module_platform_driver(intel_s10_phy_driver);

MODULE_DESCRIPTION("Intel HSSI Ethernet Phy");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" INTEL_S10_PHY_DRV_NAME);
