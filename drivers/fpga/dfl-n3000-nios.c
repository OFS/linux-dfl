// SPDX-License-Identifier: GPL-2.0
/*
 * DFL device driver for Nios private feature on Intel PAC (Programmable
 * Acceleration Card) N3000
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Xu Yilun <yilun.xu@intel.com>
 */
#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/stddef.h>
#include <linux/spi/altera.h>
#include <linux/spi/spi.h>
#include <linux/types.h>

#include "dfl.h"

static char *fec_mode = "rs";
module_param(fec_mode, charp, 0444);
MODULE_PARM_DESC(fec_mode, "FEC mode of the ethernet retimer on Intel PAC N3000");

/* N3000 Nios private feature registers */
#define NIOS_SPI_PARAM			0x8
#define PARAM_SHIFT_MODE_MSK		BIT_ULL(1)
#define PARAM_SHIFT_MODE_MSB		0
#define PARAM_SHIFT_MODE_LSB		1
#define PARAM_DATA_WIDTH		GENMASK_ULL(7, 2)
#define PARAM_NUM_CS			GENMASK_ULL(13, 8)
#define PARAM_CLK_POL			BIT_ULL(14)
#define PARAM_CLK_PHASE			BIT_ULL(15)
#define PARAM_PERIPHERAL_ID		GENMASK_ULL(47, 32)

#define NIOS_SPI_CTRL			0x10
#define CTRL_WR_DATA			GENMASK_ULL(31, 0)
#define CTRL_ADDR			GENMASK_ULL(44, 32)
#define CTRL_CMD_MSK			GENMASK_ULL(63, 62)
#define CTRL_CMD_NOP			0
#define CTRL_CMD_RD			1
#define CTRL_CMD_WR			2

#define NIOS_SPI_STAT			0x18
#define STAT_RD_DATA			GENMASK_ULL(31, 0)
#define STAT_RW_VAL			BIT_ULL(32)

/* Nios handshake registers, indirect access */
#define NIOS_INIT			0x1000
#define NIOS_INIT_DONE			BIT(0)
#define NIOS_INIT_START			BIT(1)
/* Mode for retimer A, link 0, the same below */
#define REQ_FEC_MODE_A0_MSK		GENMASK(9, 8)
#define REQ_FEC_MODE_A1_MSK		GENMASK(11, 10)
#define REQ_FEC_MODE_A2_MSK		GENMASK(13, 12)
#define REQ_FEC_MODE_A3_MSK		GENMASK(15, 14)
#define REQ_FEC_MODE_B0_MSK		GENMASK(17, 16)
#define REQ_FEC_MODE_B1_MSK		GENMASK(19, 18)
#define REQ_FEC_MODE_B2_MSK		GENMASK(21, 20)
#define REQ_FEC_MODE_B3_MSK		GENMASK(23, 22)
#define REQ_FEC_MODE_NO			0x0
#define REQ_FEC_MODE_KR			0x1
#define REQ_FEC_MODE_RS			0x2

#define NIOS_FW_VERSION			0x1004
#define NIOS_FW_VERSION_PATCH		GENMASK(23, 20)
#define NIOS_FW_VERSION_MINOR		GENMASK(27, 24)
#define NIOS_FW_VERSION_MAJOR		GENMASK(31, 28)

/* The retimers we use on Intel PAC N3000 is Parkvale, abbreviated to PKVL */
#define PKVL_A_MODE_STS			0x1020
#define PKVL_B_MODE_STS			0x1024
#define PKVL_MODE_STS_GROUP_MSK		GENMASK(15, 8)
#define PKVL_MODE_STS_GROUP_OK		0x0
#define PKVL_MODE_STS_ID_MSK		GENMASK(7, 0)
/* When GROUP MASK field == GROUP_OK  */
#define PKVL_MODE_ID_RESET		0x0
#define PKVL_MODE_ID_4X10G		0x1
#define PKVL_MODE_ID_4X25G		0x2
#define PKVL_MODE_ID_2X25G		0x3
#define PKVL_MODE_ID_2X25G_2X10G	0x4
#define PKVL_MODE_ID_1X25G		0x5

#define NS_REGBUS_WAIT_TIMEOUT		10000		/* loop count */
#define NIOS_INIT_TIMEOUT		10000000	/* usec */
#define NIOS_INIT_TIME_INTV		100000		/* usec */

struct n3000_nios {
	void __iomem *base;
	struct regmap *regmap;
	struct device *dev;
	struct platform_device *altera_spi;
};

static ssize_t nios_fw_version_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct n3000_nios *ns = dev_get_drvdata(dev);
	unsigned int val;
	int ret;

	ret = regmap_read(ns->regmap, NIOS_FW_VERSION, &val);
	if (ret)
		return ret;

	return sprintf(buf, "%x.%x.%x\n",
		       (u8)FIELD_GET(NIOS_FW_VERSION_MAJOR, val),
		       (u8)FIELD_GET(NIOS_FW_VERSION_MINOR, val),
		       (u8)FIELD_GET(NIOS_FW_VERSION_PATCH, val));
}
static DEVICE_ATTR_RO(nios_fw_version);

#define IS_MODE_STATUS_OK(mode_stat)				\
	(FIELD_GET(PKVL_MODE_STS_GROUP_MSK, (mode_stat)) ==	\
	 PKVL_MODE_STS_GROUP_OK)

#define IS_RETIMER_FEC_SUPPORTED(retimer_mode)	\
	((retimer_mode) != PKVL_MODE_ID_RESET &&	\
	 (retimer_mode) != PKVL_MODE_ID_4X10G)

static int get_retimer_mode(struct n3000_nios *ns, unsigned int mode_stat_reg,
			    unsigned int *retimer_mode)
{
	unsigned int val;
	int ret;

	ret = regmap_read(ns->regmap, mode_stat_reg, &val);
	if (ret)
		return ret;

	if (!IS_MODE_STATUS_OK(val))
		return -EFAULT;

	*retimer_mode = FIELD_GET(PKVL_MODE_STS_ID_MSK, val);

	return 0;
}

static ssize_t fec_mode_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct n3000_nios *ns = dev_get_drvdata(dev);
	unsigned int val, retimer_a_mode, retimer_b_mode, fec_mode;
	int ret;

	/* FEC mode setting is not supported in early FW versions */
	ret = regmap_read(ns->regmap, NIOS_FW_VERSION, &val);
	if (ret)
		return ret;

	if (FIELD_GET(NIOS_FW_VERSION_MAJOR, val) < 3)
		return sprintf(buf, "not supported\n");

	/* If no 25G links, FEC mode setting is not supported either */
	ret = get_retimer_mode(ns, PKVL_A_MODE_STS, &retimer_a_mode);
	if (ret)
		return ret;

	ret = get_retimer_mode(ns, PKVL_B_MODE_STS, &retimer_b_mode);
	if (ret)
		return ret;

	if (!IS_RETIMER_FEC_SUPPORTED(retimer_a_mode) &&
	    !IS_RETIMER_FEC_SUPPORTED(retimer_b_mode))
		return sprintf(buf, "not supported\n");

	/* get the valid FEC mode for 25G links */
	ret = regmap_read(ns->regmap, NIOS_INIT, &val);
	if (ret)
		return ret;

	/*
	 * FEC mode should always be the same for all links, as we set them
	 * in this way.
	 */
	fec_mode = FIELD_GET(REQ_FEC_MODE_A0_MSK, val);
	if (fec_mode != FIELD_GET(REQ_FEC_MODE_A1_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_A2_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_A3_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_B0_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_B1_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_B2_MSK, val) ||
	    fec_mode != FIELD_GET(REQ_FEC_MODE_B3_MSK, val))
		return -EFAULT;

	switch (fec_mode) {
	case REQ_FEC_MODE_NO:
		return sprintf(buf, "no\n");
	case REQ_FEC_MODE_KR:
		return sprintf(buf, "kr\n");
	case REQ_FEC_MODE_RS:
		return sprintf(buf, "rs\n");
	}

	return -EFAULT;
}
static DEVICE_ATTR_RO(fec_mode);

static struct attribute *n3000_nios_attrs[] = {
	&dev_attr_nios_fw_version.attr,
	&dev_attr_fec_mode.attr,
	NULL,
};
ATTRIBUTE_GROUPS(n3000_nios);

static int init_error_detected(struct n3000_nios *ns)
{
	unsigned int val;

	if (regmap_read(ns->regmap, PKVL_A_MODE_STS, &val))
		return true;

	if (!IS_MODE_STATUS_OK(val))
		return true;

	if (regmap_read(ns->regmap, PKVL_B_MODE_STS, &val))
		return true;

	if (!IS_MODE_STATUS_OK(val))
		return true;

	return false;
}

static void dump_error_stat(struct n3000_nios *ns)
{
	unsigned int val;

	if (regmap_read(ns->regmap, PKVL_A_MODE_STS, &val))
		return;

	dev_err(ns->dev, "PKVL_A_MODE_STS 0x%x\n", val);

	if (regmap_read(ns->regmap, PKVL_B_MODE_STS, &val))
		return;

	dev_err(ns->dev, "PKVL_B_MODE_STS 0x%x\n", val);
}

static int n3000_nios_init_done_check(struct n3000_nios *ns)
{
	struct device *dev = ns->dev;
	unsigned int val, mode;
	int ret;

	/*
	 * this SPI is shared by Nios core inside FPGA, Nios will use this SPI
	 * master to do some one time initialization after power up, and then
	 * release the control to OS. driver needs to poll on INIT_DONE to
	 * see when driver could take the control.
	 *
	 * Please note that after Nios firmware version 3.0.0, INIT_START is
	 * introduced, so driver needs to trigger START firstly and then check
	 * INIT_DONE.
	 */

	ret = regmap_read(ns->regmap, NIOS_FW_VERSION, &val);
	if (ret)
		return ret;

	/*
	 * If Nios version register is totally uninitialized(== 0x0), then the
	 * Nios firmware is missing. So host could take control of SPI master
	 * safely, but initialization work for Nios is not done. To restore the
	 * card, we need to reprogram a new Nios firmware via the BMC chip on
	 * SPI bus. So the driver doesn't error out, it continues to create the
	 * spi controller device and spi_board_info for BMC.
	 */
	if (val == 0) {
		dev_err(dev, "Nios version reg = 0x%x, skip INIT_DONE check, but the retimer may be uninitialized\n",
			val);
		return 0;
	}

	if (FIELD_GET(NIOS_FW_VERSION_MAJOR, val) >= 3) {
		/* read NIOS_INIT to check if retimer initialization is done */
		ret = regmap_read(ns->regmap, NIOS_INIT, &val);
		if (ret)
			return ret;

		/* check if retimers are initialized already */
		if (val & NIOS_INIT_DONE || val & NIOS_INIT_START)
			goto nios_init_done;

		/* configure FEC mode per module param */
		val = NIOS_INIT_START;

		/*
		 * When the retimer is to be set to 10G mode, there is no FEC
		 * mode setting, so the REQ_FEC_MODE field will be ignored by
		 * Nios firmware in this case. But we should still fill the FEC
		 * mode field cause host could not get the retimer working mode
		 * until the Nios init is done.
		 */
		if (!strcmp(fec_mode, "no"))
			mode = REQ_FEC_MODE_NO;
		else if (!strcmp(fec_mode, "kr"))
			mode = REQ_FEC_MODE_KR;
		else if (!strcmp(fec_mode, "rs"))
			mode = REQ_FEC_MODE_RS;
		else
			return -EINVAL;

		/* set the same FEC mode for all links */
		val |= FIELD_PREP(REQ_FEC_MODE_A0_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_A1_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_A2_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_A3_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_B0_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_B1_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_B2_MSK, mode) |
		       FIELD_PREP(REQ_FEC_MODE_B3_MSK, mode);

		ret = regmap_write(ns->regmap, NIOS_INIT, val);
		if (ret)
			return ret;
	}

nios_init_done:
	/* polls on NIOS_INIT_DONE */
	ret = regmap_read_poll_timeout(ns->regmap, NIOS_INIT, val,
				       val & NIOS_INIT_DONE,
				       NIOS_INIT_TIME_INTV,
				       NIOS_INIT_TIMEOUT);
	if (ret) {
		dev_err(dev, "NIOS_INIT_DONE %s\n",
			(ret == -ETIMEDOUT) ? "timed out" : "check error");
		goto dump_sts;
	}

	/*
	 * After INIT_DONE is detected, it still needs to check if any error
	 * detected.
	 */
	if (init_error_detected(ns)) {
		/*
		 * If the retimer configuration is failed, the Nios firmware
		 * will still release the spi controller for host to
		 * communicate with the BMC. It makes possible for people to
		 * reprogram a new Nios firmware and restore the card. So the
		 * driver doesn't error out, it continues to create the spi
		 * controller device and spi_board_info for BMC.
		 */
		dev_err(dev, "NIOS_INIT_DONE OK, but err found during init\n");
		goto dump_sts;
	}
	return 0;

dump_sts:
	dump_error_stat(ns);

	return ret;
}

struct spi_board_info m10_n3000_info = {
	.modalias = "m10-n3000",
	.max_speed_hz = 12500000,
	.bus_num = 0,
	.chip_select = 0,
};

static int create_altera_spi_controller(struct n3000_nios *ns)
{
	struct altera_spi_platform_data pdata = { 0 };
	struct platform_device_info pdevinfo = { 0 };
	void __iomem *base = ns->base;
	u64 v;

	v = readq(base + NIOS_SPI_PARAM);

	pdata.mode_bits = SPI_CS_HIGH;
	if (FIELD_GET(PARAM_CLK_POL, v))
		pdata.mode_bits |= SPI_CPOL;
	if (FIELD_GET(PARAM_CLK_PHASE, v))
		pdata.mode_bits |= SPI_CPHA;

	pdata.num_chipselect = FIELD_GET(PARAM_NUM_CS, v);
	pdata.bits_per_word_mask =
		SPI_BPW_RANGE_MASK(1, FIELD_GET(PARAM_DATA_WIDTH, v));

	pdata.num_devices = 1;
	pdata.devices = &m10_n3000_info;

	dev_dbg(ns->dev, "%s cs %u bpm 0x%x mode 0x%x\n", __func__,
		pdata.num_chipselect, pdata.bits_per_word_mask,
		pdata.mode_bits);

	pdevinfo.name = "subdev_spi_altera";
	pdevinfo.id = PLATFORM_DEVID_AUTO;
	pdevinfo.parent = ns->dev;
	pdevinfo.data = &pdata;
	pdevinfo.size_data = sizeof(pdata);

	ns->altera_spi = platform_device_register_full(&pdevinfo);
	return PTR_ERR_OR_ZERO(ns->altera_spi);
}

static void destroy_altera_spi_controller(struct n3000_nios *ns)
{
	platform_device_unregister(ns->altera_spi);
}

/* ns is the abbreviation of nios_spi */
static int ns_poll_stat_timeout(void __iomem *base, u64 *v)
{
	int loops = NS_REGBUS_WAIT_TIMEOUT;

	/*
	 * We don't use the time based timeout here for performance.
	 *
	 * The regbus read/write is on the critical path of Intel PAC N3000
	 * image programing. The time based timeout checking will add too much
	 * overhead on it. Usually the state changes in 1 or 2 loops on the
	 * test server, and we set 10000 times loop here for safety.
	 */
	do {
		*v = readq(base + NIOS_SPI_STAT);
		if (*v & STAT_RW_VAL)
			break;
		cpu_relax();
	} while (--loops);

	return loops ? 0 : -ETIMEDOUT;
}

static int ns_reg_write(void *context, unsigned int reg, unsigned int val)
{
	struct n3000_nios *ns = context;
	u64 v = 0;
	int ret;

	v |= FIELD_PREP(CTRL_CMD_MSK, CTRL_CMD_WR);
	v |= FIELD_PREP(CTRL_ADDR, reg);
	v |= FIELD_PREP(CTRL_WR_DATA, val);
	writeq(v, ns->base + NIOS_SPI_CTRL);

	ret = ns_poll_stat_timeout(ns->base, &v);
	if (ret)
		dev_err(ns->dev, "fail to write reg 0x%x val 0x%x: %d\n",
			reg, val, ret);

	return ret;
}

static int ns_reg_read(void *context, unsigned int reg, unsigned int *val)
{
	struct n3000_nios *ns = context;
	u64 v = 0;
	int ret;

	v |= FIELD_PREP(CTRL_CMD_MSK, CTRL_CMD_RD);
	v |= FIELD_PREP(CTRL_ADDR, reg);
	writeq(v, ns->base + NIOS_SPI_CTRL);

	ret = ns_poll_stat_timeout(ns->base, &v);
	if (ret)
		dev_err(ns->dev, "fail to read reg 0x%x: %d\n", reg, ret);
	else
		*val = FIELD_GET(STAT_RD_DATA, v);

	return ret;
}

static const struct regmap_config ns_regbus_cfg = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.fast_io = true,

	.reg_write = ns_reg_write,
	.reg_read = ns_reg_read,
};

static int n3000_nios_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct n3000_nios *ns;
	int ret;

	ns = devm_kzalloc(dev, sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return -ENOMEM;

	dev_set_drvdata(&dfl_dev->dev, ns);

	ns->dev = dev;

	ns->base = devm_ioremap_resource(&dfl_dev->dev, &dfl_dev->mmio_res);
	if (IS_ERR(ns->base))
		return PTR_ERR(ns->base);

	ns->regmap = devm_regmap_init(dev, NULL, ns, &ns_regbus_cfg);
	if (IS_ERR(ns->regmap))
		return PTR_ERR(ns->regmap);

	ret = n3000_nios_init_done_check(ns);
	if (ret)
		return ret;

	ret = create_altera_spi_controller(ns);
	if (ret)
		dev_err(dev, "altera spi controller create failed: %d\n", ret);

	return ret;
}

static void n3000_nios_remove(struct dfl_device *dfl_dev)
{
	struct n3000_nios *ns = dev_get_drvdata(&dfl_dev->dev);

	destroy_altera_spi_controller(ns);
}

#define FME_FEATURE_ID_N3000_NIOS	0xd

static const struct dfl_device_id n3000_nios_ids[] = {
	{ FME_ID, FME_FEATURE_ID_N3000_NIOS },
	{ }
};

static struct dfl_driver n3000_nios_driver = {
	.drv	= {
		.name       = "n3000-nios",
		.dev_groups = n3000_nios_groups,
	},
	.id_table = n3000_nios_ids,
	.probe   = n3000_nios_probe,
	.remove  = n3000_nios_remove,
};

module_dfl_driver(n3000_nios_driver);

MODULE_DEVICE_TABLE(dfl, n3000_nios_ids);
MODULE_DESCRIPTION("Driver for Nios private feature on Intel PAC N3000");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
