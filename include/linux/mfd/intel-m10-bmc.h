/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver Header File for Intel Max10 Board Management Controller chip.
 *
 * Copyright (C) 2018-2020 Intel Corporation, Inc.
 *
 */
#ifndef __INTEL_M10_BMC_H
#define __INTEL_M10_BMC_H

#include <linux/regmap.h>

#define M10BMC_LEGACY_SYS_BASE		0x300400
#define M10BMC_SYS_BASE		0x300800
#define M10BMC_MEM_END		0x200000fc

/* Register offset of system registers */
#define NIOS2_FW_VERSION	0x0
#define M10BMC_TEST_REG		0x3c
#define M10BMC_BUILD_VER	0x68
#define   M10BMC_VERSION_MAJOR	GENMASK(23, 16)
#define   PCB_INFO		GENMASK(31, 24)

/**
 * struct intel_m10bmc - Intel Max10 BMC MFD device private data structure
 * @dev: this device
 * @regmap: the regmap used to access registers by m10bmc itself
 */
struct intel_m10bmc {
	struct device *dev;
	struct regmap *regmap;
};

/*
 * register access helper functions.
 *
 * m10bmc_raw_read - read m10bmc register per addr
 * m10bmc_sys_read - read m10bmc system register per offset
 */
static inline int
m10bmc_raw_read(struct intel_m10bmc *m10bmc, unsigned int addr,
		unsigned int *val)
{
	int ret;

	ret = regmap_read(m10bmc->regmap, addr, val);
	if (ret)
		dev_err(m10bmc->dev, "fail to read raw reg %x: %d\n",
			addr, ret);

	return ret;
}

#define m10bmc_sys_read(m10bmc, offset, val) \
	m10bmc_raw_read(m10bmc, M10BMC_SYS_BASE + (offset), val)

/* M10BMC system sub devices for PAC N3000 */
/* subdev hwmon  */
#define N3000BMC_HWMON_DEV_NAME         "n3000bmc-hwmon"

#endif /* __INTEL_M10_BMC_H */
