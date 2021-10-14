// SPDX-License-Identifier: GPL-2.0
/*
 * DFL device driver for ToD private feature
 *
 * Copyright (C) 2021 Intel Corporation, Inc.
 *
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dfl.h>
#include <linux/gcd.h>
#include <linux/io.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ptp_clock_kernel.h>

#define FME_FEATURE_ID_TOD		0x22

#define NOMINAL_PPB			1000000000ULL
#define TOD_PERIOD_MAX			0xfffff
#define TOD_PERIOD_MIN			0
#define TOD_DRIFT_ADJUST_FNS_MAX	0xffff
#define TOD_DRIFT_ADJUST_RATE_MAX	0xffff
#define TOD_ADJUST_COUNT_MAX		0xfffff
#define TOD_ADJUST_MS_MAX		(((((TOD_PERIOD_MAX) >> 16) + 1) * \
					  ((TOD_ADJUST_COUNT_MAX) + 1)) /  \
					 1000000UL)

/* Time-of-Day (ToD) clock register space. */
#define CLK_F				0x38
#define SECONDSH			0x100
#define SECONDSL			0x104
#define NANOSEC				0x108
#define PERIOD				0x110
#define ADJUST_PERIOD			0x114
#define ADJUST_COUNT			0x118
#define DRIFT_ADJUST			0x11c
#define DRIFT_ADJUST_RATE		0x120

struct dfl_tod {
	struct device *dev;
	struct ptp_clock_info ptp_clock_ops;
	struct ptp_clock *ptp_clock;

	/* Time-of-Day (ToD) Clock address space */
	void __iomem *tod_ctrl;

	/* ToD clock registers protection */
	spinlock_t tod_lock;
};

/* A fine ToD HW clock offset adjustment.
 * To perform the fine offset adjustment the AdjustPeriod register is used
 * to replace the Period register for AdjustCount clock cycles in hardware.
 * The dt->tod_lock spinlock must be held when calling this function.
 */
static int fine_adjust_tod_clock(struct dfl_tod *dt, u32 adjust_period,
				 u32 adjust_count)
{
	void __iomem *base = dt->tod_ctrl;
	int limit;

	writel(adjust_period, base + ADJUST_PERIOD);
	writel(adjust_count, base + ADJUST_COUNT);

	/* Wait for present offset adjustment update to complete */
	limit = TOD_ADJUST_MS_MAX;
	while (limit--) {
		if (!readl(base + ADJUST_COUNT))
			break;
		mdelay(1);
	}
	if (limit < 0)
		return -EBUSY;
	return 0;
}

/* A coarse ToD HW clock offset adjustment.
 * The coarse time adjustment performs by adding or subtracting the delta value
 * from the current ToD HW clock time.
 * The dt->tod_lock spinlock must be held when calling this function.
 */
static int coarse_adjust_tod_clock(struct dfl_tod *dt, s64 delta)
{
	u32 seconds_msb, seconds_lsb, nanosec;
	void __iomem *base = dt->tod_ctrl;
	u64 seconds, now;

	if (delta == 0)
		return 0;

	/* Get current time */
	nanosec = readl(base + NANOSEC);
	seconds_lsb = readl(base + SECONDSL);
	seconds_msb = readl(base + SECONDSH);

	/* Calculate new time */
	seconds = (((u64)(seconds_msb & 0x0000ffff)) << 32) | seconds_lsb;
	now = seconds * NSEC_PER_SEC + nanosec + delta;

	seconds = div_u64_rem(now, NSEC_PER_SEC, &nanosec);
	seconds_msb = upper_32_bits(seconds) & 0x0000ffff;
	seconds_lsb = lower_32_bits(seconds);

	/* Set corrected time */
	writel(seconds_msb, base + SECONDSH);
	writel(seconds_lsb, base + SECONDSL);
	writel(nanosec, base + NANOSEC);

	return 0;
}

static int dfl_tod_adjust_fine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct dfl_tod *dt = container_of(ptp, struct dfl_tod, ptp_clock_ops);
	u32 tod_period, tod_rem, tod_drift_adjust_fns, tod_drift_adjust_rate;
	void __iomem *base = dt->tod_ctrl;
	unsigned long flags, rate;
	u64 ppb;

	/* Get the clock rate from clock frequency register offset */
	rate = readl(base + CLK_F);

	/* From scaled_ppm_to_ppb */
	ppb = 1 + scaled_ppm;
	ppb *= 125;
	ppb >>= 13;

	ppb += NOMINAL_PPB;

	tod_period = div_u64_rem(ppb << 16, rate, &tod_rem);
	if (tod_period > TOD_PERIOD_MAX)
		return -ERANGE;

	/* The drift of ToD adjusted periodically by adding a drift_adjust_fns
	 * correction value every drift_adjust_rate count of clock cycles.
	 */
	tod_drift_adjust_fns = tod_rem / gcd(tod_rem, rate);
	tod_drift_adjust_rate = rate / gcd(tod_rem, rate);

	while ((tod_drift_adjust_fns > TOD_DRIFT_ADJUST_FNS_MAX) |
		(tod_drift_adjust_rate > TOD_DRIFT_ADJUST_RATE_MAX)) {
		tod_drift_adjust_fns = tod_drift_adjust_fns >> 1;
		tod_drift_adjust_rate = tod_drift_adjust_rate >> 1;
	}

	if (tod_drift_adjust_fns == 0)
		tod_drift_adjust_rate = 0;

	spin_lock_irqsave(&dt->tod_lock, flags);
	writel(tod_period, base + PERIOD);
	writel(0, base + ADJUST_PERIOD);
	writel(0, base + ADJUST_COUNT);
	writel(tod_drift_adjust_fns, base + DRIFT_ADJUST);
	writel(tod_drift_adjust_rate, base + DRIFT_ADJUST_RATE);
	spin_unlock_irqrestore(&dt->tod_lock, flags);

	return 0;
}

static int dfl_tod_adjust_time(struct ptp_clock_info *ptp, s64 delta)
{
	struct dfl_tod *dt = container_of(ptp, struct dfl_tod, ptp_clock_ops);
	u32 period, diff, rem, rem_period, adj_period;
	void __iomem *base = dt->tod_ctrl;
	int neg_adj = 0, ret = 0;
	unsigned long flags;
	u64 count;

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}

	spin_lock_irqsave(&dt->tod_lock, flags);

	/* Get the maximum possible value of the Period register offset
	 * adjustment in nanoseconds scale. This depends on the current
	 * Period register setting and the maximum and minimum possible
	 * values of the Period register.
	 */
	period = readl(base + PERIOD);

	if (neg_adj)
		diff = (period - TOD_PERIOD_MIN) >> 16;
	else
		diff = (TOD_PERIOD_MAX - period) >> 16;

	/* Find the number of cycles required for the
	 * time adjustment
	 */
	count = div_u64_rem(delta, diff, &rem);

	if (neg_adj) {
		adj_period = period - (diff << 16);
		rem_period = period - (rem << 16);
	} else {
		adj_period = period + (diff << 16);
		rem_period = period + (rem << 16);
	}

	/* If count is larger than the maximum count,
	 * just set the time.
	 */
	if (count > TOD_ADJUST_COUNT_MAX) {
		/* Perform the coarse time offset adjustment */
		ret = coarse_adjust_tod_clock(dt, delta);
	} else {
		/* Adjust the period for count cycles to adjust the time */
		if (count)
			ret = fine_adjust_tod_clock(dt, adj_period, count);

		/* If there is a remainder, adjust the period for an
		 * additional cycle
		 */
		if (rem)
			ret = fine_adjust_tod_clock(dt, rem_period, 1);
	}

	spin_unlock_irqrestore(&dt->tod_lock, flags);

	return ret;
}

static int dfl_tod_get_time(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct dfl_tod *dt = container_of(ptp, struct dfl_tod, ptp_clock_ops);
	u32 seconds_msb, seconds_lsb, nanosec;
	void __iomem *base = dt->tod_ctrl;
	unsigned long flags;
	u64 seconds;

	spin_lock_irqsave(&dt->tod_lock, flags);
	nanosec = readl(base + NANOSEC);
	seconds_lsb = readl(base + SECONDSL);
	seconds_msb = readl(base + SECONDSH);
	spin_unlock_irqrestore(&dt->tod_lock, flags);

	seconds = (((u64)(seconds_msb & 0x0000ffff)) << 32) | seconds_lsb;

	ts->tv_nsec = nanosec;
	ts->tv_sec = (__kernel_old_time_t)seconds;

	return 0;
}

static int dfl_tod_set_time(struct ptp_clock_info *ptp,
			    const struct timespec64 *ts)
{
	struct dfl_tod *dt = container_of(ptp, struct dfl_tod, ptp_clock_ops);
	u32 seconds_msb = upper_32_bits(ts->tv_sec) & 0x0000ffff;
	u32 seconds_lsb = lower_32_bits(ts->tv_sec);
	u32 nanosec = lower_32_bits(ts->tv_nsec);
	void __iomem *base = dt->tod_ctrl;
	unsigned long flags;

	spin_lock_irqsave(&dt->tod_lock, flags);
	writel(seconds_msb, base + SECONDSH);
	writel(seconds_lsb, base + SECONDSL);
	writel(nanosec, base + NANOSEC);
	spin_unlock_irqrestore(&dt->tod_lock, flags);

	return 0;
}

static int dfl_tod_enable_feature(struct ptp_clock_info *ptp,
				  struct ptp_clock_request *request, int on)
{
	return -EOPNOTSUPP;
}

static struct ptp_clock_info dfl_tod_clock_ops = {
	.owner = THIS_MODULE,
	.name = "dfl_tod",
	.max_adj = 500000000,
	.n_alarm = 0,
	.n_ext_ts = 0,
	.n_per_out = 0,
	.pps = 0,
	.adjfine = dfl_tod_adjust_fine,
	.adjtime = dfl_tod_adjust_time,
	.gettime64 = dfl_tod_get_time,
	.settime64 = dfl_tod_set_time,
	.enable = dfl_tod_enable_feature,
};

static int dfl_tod_probe(struct dfl_device *ddev)
{
	struct device *dev = &ddev->dev;
	struct dfl_tod *dt;

	dt = devm_kzalloc(dev, sizeof(*dt), GFP_KERNEL);
	if (!dt)
		return -ENOMEM;

	/* Time-of-Day (ToD) Clock address space */
	dt->tod_ctrl = devm_ioremap_resource(dev, &ddev->mmio_res);
	if (IS_ERR(dt->tod_ctrl))
		return PTR_ERR(dt->tod_ctrl);

	dt->dev = dev;
	spin_lock_init(&dt->tod_lock);
	dev_set_drvdata(dev, dt);

	dev_info(&ddev->dev, "\tTOD Ctrl at 0x%08lx\n",
		 (unsigned long)ddev->mmio_res.start);

	/* Register the PTP clock driver to the kernel */
	dt->ptp_clock_ops = dfl_tod_clock_ops;

	dt->ptp_clock = ptp_clock_register(&dt->ptp_clock_ops, dev);
	if (IS_ERR(dt->ptp_clock)) {
		dev_err(&ddev->dev, "Unable to register PTP clock\n");
		dt->ptp_clock = NULL;
		return PTR_ERR(dt->ptp_clock);
	}

	return 0;
}

static void dfl_tod_remove(struct dfl_device *ddev)
{
	struct dfl_tod *dt = dev_get_drvdata(&ddev->dev);

	/* Unregister the PTP clock driver from the kernel */
	if (dt->ptp_clock) {
		ptp_clock_unregister(dt->ptp_clock);
		dt->ptp_clock = NULL;
	}
}

static const struct dfl_device_id dfl_tod_ids[] = {
		{ FME_ID, FME_FEATURE_ID_TOD },
		{ }
};
MODULE_DEVICE_TABLE(dfl, dfl_tod_ids);

static struct dfl_driver dfl_tod_driver = {
	.drv = {
		.name = "dfl-tod",
	},
	.id_table = dfl_tod_ids,
	.probe = dfl_tod_probe,
	.remove = dfl_tod_remove,
};
module_dfl_driver(dfl_tod_driver);

MODULE_DESCRIPTION("DFL ToD driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
