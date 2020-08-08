// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for DFL IOPLL User Clock private feature
 *
 * Copyright 2019-2020 Intel Corporation, Inc.
 */

#include <linux/dfl.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/iopoll.h>
#include <uapi/linux/intel-dfl-iopll.h>
#include <linux/module.h>

#include "dfl.h"

struct dfl_iopll {
	void __iomem *csr_base;
	struct device *dev;
	struct mutex iopll_mutex;	/* Serialize access to iopll */
};

/*
 * IOPLL CSR register definitions
 */
#define IOPLL_FREQ_CMD0		0x8
/* Field definitions for both IOPLL_FREQ_CMD0 and IOPLL_FREQ_STS0 */
#define   IOPLL_DATA		GENMASK_ULL(31, 0)
#define   IOPLL_ADDR		GENMASK_ULL(41, 32)
#define   IOPLL_WRITE		BIT_ULL(44)
#define   IOPLL_SEQ		GENMASK_ULL(49, 48)
#define   IOPLL_AVMM_RESET_N	BIT_ULL(52)
#define   IOPLL_MGMT_RESET	BIT_ULL(56)
#define   IOPLL_RESET		BIT_ULL(57)

#define IOPLL_FREQ_CMD1		0x10
/* Field definitions for both IOPLL_FREQ_CMD1 and IOPLL_FREQ_STS1 */
#define   IOPLL_CLK_MEASURE	BIT_ULL(32)	/* Measure clk: 0=1x, 1=2x */

#define IOPLL_FREQ_STS0		0x18
#define   IOPLL_LOCKED		BIT_ULL(60)
#define   IOPLL_AVMM_ERROR	BIT_ULL(63)

#define IOPLL_FREQ_STS1		0x20
#define   IOPLL_FREQUENCY	GENMASK_ULL(16, 0)	/* 10 kHz units */
#define   IOPLL_REF_FREQ	GENMASK_ULL(50, 33)	/* Reference Freq */
#define   IOPLL_VERSION		GENMASK_ULL(63, 60)	/* User clock version */

/*
 * Control and status registers for the IOPLL
 * https://www.altera.com/en_US/pdfs/literature/hb/stratix-10/ug-s10-clkpll.pdf
 * Section 7.2
 */

#define CFG_PLL_LOW			GENMASK_ULL(7, 0)
#define CFG_PLL_HIGH			GENMASK_ULL(15, 8)
#define CFG_PLL_BYPASS_EN		BIT_ULL(16)
#define CFG_PLL_EVEN_DUTY_EN		BIT_ULL(17)

#define PLL_EVEN_DUTY_EN_SHIFT	7

#define PLL_N_HIGH_ADDR			0x100
#define PLL_N_BYPASS_EN_ADDR		0x101 /* Same as PLL_CP1_ADDR */
#define PLL_N_EVEN_DUTY_EN_ADDR		0x101 /* Same as PLL_CP1_ADDR */
#define PLL_N_LOW_ADDR			0x102

#define PLL_M_HIGH_ADDR			0x104
#define PLL_M_BYPASS_EN_ADDR		0x105
#define PLL_M_EVEN_DUTY_EN_ADDR		0x106
#define PLL_M_LOW_ADDR			0x107

#define PLL_C0_HIGH_ADDR		0x11b
#define PLL_C0_BYPASS_EN_ADDR		0x11c
#define PLL_C0_EVEN_DUTY_EN_ADDR	0x11d
#define PLL_C0_LOW_ADDR			0x11e

#define PLL_C1_HIGH_ADDR		0x11f
#define PLL_C1_BYPASS_EN_ADDR		0x120
#define PLL_C1_EVEN_DUTY_EN_ADDR	0x121
#define PLL_C1_LOW_ADDR			0x122

#define CFG_PLL_CP1			GENMASK_ULL(2, 0)
#define PLL_CP1_ADDR			0x101 /* Same as PLL_N_BYPASS_EN_ADDR */
#define PLL_CP1_SHIFT			4

#define CFG_PLL_LF			GENMASK_ULL(13, 6)
#define PLL_LF_ADDR			0x10a
#define PLL_LF_SHIFT			3

#define CFG_PLL_CP2			GENMASK_ULL(5, 3)
#define PLL_CP2_ADDR			0x10d
#define PLL_CP2_SHIFT			5

#define CFG_PLL_RC			GENMASK_ULL(1, 0)
#define PLL_RC_SHIFT			1

#define PLL_REQUEST_CAL_ADDR		0x149
#define PLL_REQUEST_CALIBRATION		BIT(6)

#define PLL_ENABLE_CAL_ADDR		0x14a
#define PLL_ENABLE_CALIBRATION		0x03

#define IOPLL_MEASURE_LOW		0
#define IOPLL_MEASURE_HIGH		1
#define IOPLL_MEASURE_DELAY_MS		4
#define IOPLL_RESET_DELAY_MS		1
#define IOPLL_CAL_DELAY_MS		1

#define	FREQ_IN_KHZ(freq)		((freq) * 10)

#define IOPLL_WRITE_POLL_INVL_US	10	/* Write poll interval */
#define IOPLL_WRITE_POLL_TIMEOUT_US	1000000	/* Write poll timeout */

static int iopll_reset(struct dfl_iopll *iopll)
{
	u64 v;

	dev_dbg(iopll->dev, "Reset IOPLL\n");

	/* Assert all resets. IOPLL_AVMM_RESET_N is asserted implicitly */
	v = IOPLL_MGMT_RESET | IOPLL_RESET;
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD0);

	msleep(IOPLL_RESET_DELAY_MS);

	/* De-assert the iopll reset only */
	v = IOPLL_MGMT_RESET;
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD0);

	msleep(IOPLL_RESET_DELAY_MS);

	/* De-assert the remaining resets */
	v = IOPLL_AVMM_RESET_N;
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD0);

	msleep(IOPLL_RESET_DELAY_MS);

	v = readq(iopll->csr_base + IOPLL_FREQ_STS0);
	if (!(v & IOPLL_LOCKED)) {
		dev_err(iopll->dev, "IOPLL NOT locked after reset\n");
		return -EBUSY;
	}

	return 0;
}

static int iopll_read_freq(struct dfl_iopll *iopll, u8 clock_sel, u32 *freq)
{
	u64 v;

	dev_dbg(iopll->dev, "Read Frequency: %d\n", clock_sel);

	v = readq(iopll->csr_base + IOPLL_FREQ_STS0);
	if (!(v & IOPLL_LOCKED)) {
		dev_err(iopll->dev, "IOPLL is NOT locked!\n");
		return -EBUSY;
	}

	v = FIELD_PREP(IOPLL_CLK_MEASURE, clock_sel);
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD1);

	msleep(IOPLL_MEASURE_DELAY_MS);

	v = readq(iopll->csr_base + IOPLL_FREQ_STS1);

	*freq = FIELD_GET(IOPLL_FREQUENCY, v);
	return 0;
}

static int iopll_write(struct dfl_iopll *iopll, u16 address, u32 data, u8 seq)
{
	int ret;
	u64 v;

	seq &= 0x3;

	v = FIELD_PREP(IOPLL_DATA, data);
	v |= FIELD_PREP(IOPLL_ADDR, address);
	v |= IOPLL_WRITE;
	v |= FIELD_PREP(IOPLL_SEQ, seq);
	v |= IOPLL_AVMM_RESET_N;
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD0);

	ret = readq_poll_timeout(iopll->csr_base + IOPLL_FREQ_STS0, v,
				 FIELD_GET(IOPLL_SEQ, v) == seq,
				 IOPLL_WRITE_POLL_INVL_US,
				 IOPLL_WRITE_POLL_TIMEOUT_US);
	if (ret)
		dev_err(iopll->dev, "Timeout on IOPLL write\n");

	return ret;
}

static int iopll_read(struct dfl_iopll *iopll, u16 address, u32 *data, u8 seq)
{
	int ret;
	u64 v;

	seq &= 0x3;

	v = FIELD_PREP(IOPLL_ADDR, address);
	v |= FIELD_PREP(IOPLL_SEQ, seq);
	v |= IOPLL_AVMM_RESET_N;
	writeq(v, iopll->csr_base + IOPLL_FREQ_CMD0);

	ret = readq_poll_timeout(iopll->csr_base + IOPLL_FREQ_STS0, v,
				 FIELD_GET(IOPLL_SEQ, v) == seq,
				 IOPLL_WRITE_POLL_INVL_US,
				 IOPLL_WRITE_POLL_TIMEOUT_US);
	if (ret)
		dev_err(iopll->dev, "Timeout on IOPLL read\n");
	else
		*data = FIELD_GET(IOPLL_DATA, v);

	return ret;
}

static int iopll_update_bits(struct dfl_iopll *iopll, u16 address, u32 mask,
			     u32 bits, u8 *seq)
{
	u32 data;
	int ret;

	ret = iopll_read(iopll, address, &data, (*seq)++);
	if (ret)
		return ret;

	data &= ~mask;
	data |= (bits & mask);

	return iopll_write(iopll, PLL_REQUEST_CAL_ADDR,
			   data | PLL_REQUEST_CALIBRATION, (*seq)++);
}

static int iopll_m_write(struct dfl_iopll *iopll, u32 cfg_pll_m, u8 *seq)
{
	u32 high, low, bypass_en, even_duty_en;
	int ret;

	high = FIELD_GET(CFG_PLL_HIGH, cfg_pll_m);
	ret = iopll_write(iopll, PLL_M_HIGH_ADDR, high, (*seq)++);
	if (ret)
		return ret;

	low = FIELD_GET(CFG_PLL_LOW, cfg_pll_m);
	ret = iopll_write(iopll, PLL_M_LOW_ADDR, low, (*seq)++);
	if (ret)
		return ret;

	bypass_en = FIELD_GET(CFG_PLL_BYPASS_EN, cfg_pll_m);
	ret = iopll_write(iopll, PLL_M_BYPASS_EN_ADDR, bypass_en, (*seq)++);
	if (ret)
		return ret;

	even_duty_en = FIELD_GET(CFG_PLL_EVEN_DUTY_EN, cfg_pll_m) <<
		PLL_EVEN_DUTY_EN_SHIFT;
	return iopll_write(iopll, PLL_M_EVEN_DUTY_EN_ADDR,
			   even_duty_en, (*seq)++);
}

static int iopll_n_write(struct dfl_iopll *iopll, u32 cfg_pll_n,
			 u32 cfg_pll_cp, u8 *seq)
{
	u32 high, low, bypass_en, even_duty_en, cp1;
	int ret;

	high = FIELD_GET(CFG_PLL_HIGH, cfg_pll_n);
	ret = iopll_write(iopll, PLL_N_HIGH_ADDR, high, (*seq)++);
	if (ret)
		return ret;

	low = FIELD_GET(CFG_PLL_LOW, cfg_pll_n);
	ret = iopll_write(iopll, PLL_N_LOW_ADDR, low, (*seq)++);
	if (ret)
		return ret;

	even_duty_en = FIELD_GET(CFG_PLL_EVEN_DUTY_EN, cfg_pll_n) <<
		PLL_EVEN_DUTY_EN_SHIFT;
	cp1 = FIELD_GET(CFG_PLL_CP1, cfg_pll_cp) << PLL_CP1_SHIFT;
	bypass_en = FIELD_GET(CFG_PLL_BYPASS_EN, cfg_pll_n);
	return iopll_write(iopll, PLL_N_BYPASS_EN_ADDR,
			   even_duty_en | cp1 | bypass_en, (*seq)++);
}

static int iopll_c0_write(struct dfl_iopll *iopll, u32 cfg_pll_c0, u8 *seq)
{
	u32 high, low, bypass_en, even_duty_en;
	int ret;

	high = FIELD_GET(CFG_PLL_HIGH, cfg_pll_c0);
	ret = iopll_write(iopll, PLL_C0_HIGH_ADDR, high, (*seq)++);
	if (ret)
		return ret;

	low = FIELD_GET(CFG_PLL_LOW, cfg_pll_c0);
	ret = iopll_write(iopll, PLL_C0_LOW_ADDR, low, (*seq)++);
	if (ret)
		return ret;

	bypass_en = FIELD_GET(CFG_PLL_BYPASS_EN, cfg_pll_c0);
	ret = iopll_write(iopll, PLL_C0_BYPASS_EN_ADDR, bypass_en, (*seq)++);
	if (ret)
		return ret;

	even_duty_en = FIELD_GET(CFG_PLL_EVEN_DUTY_EN, cfg_pll_c0) <<
		PLL_EVEN_DUTY_EN_SHIFT;
	return iopll_write(iopll, PLL_C0_EVEN_DUTY_EN_ADDR,
			  even_duty_en, (*seq)++);
}

static int iopll_c1_write(struct dfl_iopll *iopll, u32 cfg_pll_c1, u8 *seq)
{
	u32 high, low, bypass_en, even_duty_en;
	int ret;

	high = FIELD_GET(CFG_PLL_HIGH, cfg_pll_c1);
	ret = iopll_write(iopll, PLL_C1_HIGH_ADDR, high, (*seq)++);
	if (ret)
		return ret;

	low = FIELD_GET(CFG_PLL_LOW, cfg_pll_c1);
	ret = iopll_write(iopll, PLL_C1_LOW_ADDR, low, (*seq)++);
	if (ret)
		return ret;

	bypass_en = FIELD_GET(CFG_PLL_BYPASS_EN, cfg_pll_c1);
	ret = iopll_write(iopll, PLL_C1_BYPASS_EN_ADDR, bypass_en, (*seq)++);
	if (ret)
		return ret;

	even_duty_en = FIELD_GET(CFG_PLL_EVEN_DUTY_EN, cfg_pll_c1) <<
		PLL_EVEN_DUTY_EN_SHIFT;
	return iopll_write(iopll, PLL_C1_EVEN_DUTY_EN_ADDR,
			   even_duty_en, (*seq)++);
}

static int iopll_set_freq(struct dfl_iopll *iopll,
			  struct pll_config *c, u8 *seq)
{
	u32 cp2, lf, rc;
	int ret;

	dev_dbg(iopll->dev, "Set Frequency\n");

	ret = iopll_m_write(iopll, c->pll_m, seq);
	if (ret)
		return ret;

	ret = iopll_n_write(iopll, c->pll_n, c->pll_cp, seq);
	if (ret)
		return ret;

	ret = iopll_c0_write(iopll, c->pll_c0, seq);
	if (ret)
		return ret;

	ret = iopll_c1_write(iopll, c->pll_c1, seq);
	if (ret)
		return ret;

	cp2 = FIELD_GET(CFG_PLL_CP2, c->pll_cp) << PLL_CP2_SHIFT;
	ret = iopll_write(iopll, PLL_CP2_ADDR, cp2, (*seq)++);
	if (ret)
		return ret;

	lf = FIELD_GET(CFG_PLL_LF, c->pll_lf) << PLL_LF_SHIFT;
	rc = FIELD_GET(CFG_PLL_RC, c->pll_rc) << PLL_RC_SHIFT;
	return iopll_write(iopll, PLL_LF_ADDR, lf | rc, (*seq)++);
}

static int iopll_calibrate(struct dfl_iopll *iopll, u8 *seq)
{
	int ret;

	dev_dbg(iopll->dev, "Request Calibration\n");

	/* Request IOPLL Calibration */
	ret = iopll_update_bits(iopll, PLL_REQUEST_CAL_ADDR,
				PLL_REQUEST_CALIBRATION,
				PLL_REQUEST_CALIBRATION, seq);
	if (ret)
		return ret;

	/* Enable calibration interface */
	ret = iopll_write(iopll, PLL_ENABLE_CAL_ADDR, PLL_ENABLE_CALIBRATION,
			  (*seq)++);
	msleep(IOPLL_CAL_DELAY_MS);
	return ret;
}

static ssize_t frequency_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct dfl_iopll *iopll = dev_get_drvdata(dev);
	u32 low_freq, high_freq;
	int ret;

	dev_dbg(dev, "Userclk Frequency Show.\n");
	mutex_lock(&iopll->iopll_mutex);

	ret = iopll_read_freq(iopll, IOPLL_MEASURE_HIGH, &high_freq);
	if (ret)
		goto done;

	ret = iopll_read_freq(iopll, IOPLL_MEASURE_LOW, &low_freq);

done:
	mutex_unlock(&iopll->iopll_mutex);
	return ret ? : sprintf(buf, "%u %u\n", FREQ_IN_KHZ(low_freq),
			       FREQ_IN_KHZ(high_freq));
}

static ssize_t frequency_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct pll_config *iopll_config = (struct pll_config *)buf;
	struct dfl_iopll *iopll = dev_get_drvdata(dev);
	u8 seq = 1;
	int ret;

	dev_dbg(dev, "Userclk Frequency Store.\n");
	if (count != sizeof(struct pll_config))
		return -EINVAL;

	if ((iopll_config->pll_freq_khz > IOPLL_MAX_FREQ * 1000) ||
	    (iopll_config->pll_freq_khz < IOPLL_MIN_FREQ * 1000))
		return -EINVAL;

	mutex_lock(&iopll->iopll_mutex);

	ret = iopll_set_freq(iopll, iopll_config, &seq);
	if (ret)
		goto done;

	ret = iopll_reset(iopll);
	if (ret)
		goto done;

	ret = iopll_calibrate(iopll, &seq);

done:
	mutex_unlock(&iopll->iopll_mutex);
	return ret ? : count;
}
static DEVICE_ATTR_RW(frequency);

static ssize_t revision_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct dfl_iopll *iopll = dev_get_drvdata(dev);
	u64 v;

	dev_dbg(dev, "Userclk Version Show.\n");

	mutex_lock(&iopll->iopll_mutex);
	v = readq(iopll->csr_base + IOPLL_FREQ_STS1);
	mutex_unlock(&iopll->iopll_mutex);

	return sprintf(buf, "%llu\n", FIELD_GET(IOPLL_VERSION, v));
}
static DEVICE_ATTR_RO(revision);

static ssize_t ref_frequency_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct dfl_iopll *iopll = dev_get_drvdata(dev);
	u64 v;

	dev_dbg(dev, "Userclk Reference Frequency Show.\n");

	mutex_lock(&iopll->iopll_mutex);
	v = readq(iopll->csr_base + IOPLL_FREQ_STS1);
	mutex_unlock(&iopll->iopll_mutex);

	return sprintf(buf, "%llu\n",
		       FREQ_IN_KHZ(FIELD_GET(IOPLL_REF_FREQ, v)));
}
static DEVICE_ATTR_RO(ref_frequency);

static  struct attribute *iopll_attrs[] = {
	&dev_attr_frequency.attr,
	&dev_attr_revision.attr,
	&dev_attr_ref_frequency.attr,
	NULL,
};

static const struct attribute_group iopll_attr_group = {
	.name	= "userclk",
	.attrs	= iopll_attrs,
};

static const struct attribute_group *iopll_attr_groups[] = {
	&iopll_attr_group,
	NULL
};

static int dfl_intel_s10_iopll_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct dfl_iopll *iopll;
	void __iomem *csr_base;

	csr_base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (IS_ERR(csr_base)) {
		dev_err(dev, "Failed to get mem resource!\n");
		return PTR_ERR(csr_base);
	}

	iopll = devm_kzalloc(dev, sizeof(*iopll), GFP_KERNEL);
	if (!iopll)
		return -ENOMEM;

	iopll->csr_base = csr_base;
	iopll->dev = dev;
	mutex_init(&iopll->iopll_mutex);
	dev_set_drvdata(dev, iopll);

	return 0;
}

static void dfl_intel_s10_iopll_remove(struct dfl_device *dfl_dev)
{
	struct dfl_iopll *iopll = dev_get_drvdata(&dfl_dev->dev);

	mutex_destroy(&iopll->iopll_mutex);
}

#define PORT_FEATURE_ID_IOPLL 0x14

static const struct dfl_device_id dfl_intel_s10_iopll_ids[] = {
	{ PORT_ID, PORT_FEATURE_ID_IOPLL },
	{ }
};

static struct dfl_driver dfl_intel_s10_iopll_driver = {
	.drv = {
		.name = "intel-dfl-iopll",
		.dev_groups = iopll_attr_groups,
	},
	.id_table = dfl_intel_s10_iopll_ids,
	.probe = dfl_intel_s10_iopll_probe,
	.remove = dfl_intel_s10_iopll_remove,
};

module_dfl_driver(dfl_intel_s10_iopll_driver);

MODULE_DEVICE_TABLE(dfl, dfl_intel_s10_iopll_ids);
MODULE_DESCRIPTION("DFL Intel S10 IOPLL driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
