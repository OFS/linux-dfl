/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intel MAX 10 Board Management Controller chip.
 *
 * Copyright (C) 2018-2020 Intel Corporation, Inc.
 */
#ifndef __MFD_INTEL_M10_BMC_H
#define __MFD_INTEL_M10_BMC_H

#include <linux/regmap.h>

#define M10BMC_LEGACY_SYS_BASE		0x300400
#define M10BMC_SYS_BASE			0x300800
#define M10BMC_MEM_END			0x200000fc

/* Register offset of system registers */
#define NIOS2_FW_VERSION		0x0
#define M10BMC_MACADDR1			0x10
#define M10BMC_MAC_BYTE4		GENMASK(7, 0)
#define M10BMC_MAC_BYTE3		GENMASK(15, 8)
#define M10BMC_MAC_BYTE2		GENMASK(23, 16)
#define M10BMC_MAC_BYTE1		GENMASK(31, 24)
#define M10BMC_MACADDR2			0x14
#define M10BMC_MAC_BYTE6		GENMASK(7, 0)
#define M10BMC_MAC_BYTE5		GENMASK(15, 8)
#define M10BMC_MAC_COUNT		GENMASK(23, 16)
#define M10BMC_TEST_REG			0x3c
#define M10BMC_BUILD_VER		0x68
#define M10BMC_VER_MAJOR_MSK		GENMASK(23, 16)
#define M10BMC_VER_PCB_INFO_MSK		GENMASK(31, 24)

/* PKVL related registers, in system register region */
#define PKVL_LINK_STATUS		0x164
#define PKVL_A_VERSION			0x254
#define PKVL_B_VERSION			0x258
#define SERDES_VERSION			GENMASK(15, 0)
#define SBUS_VERSION			GENMASK(31, 16)

/**
 * struct intel_m10bmc_retimer_pdata - subdev retimer platform data
 *
 * @retimer_master: the NIC device which connects to the retimers on m10bmc
 */
struct intel_m10bmc_retimer_pdata {
	struct device *retimer_master;
};

struct intel_m10bmc_platdata {
	struct intel_m10bmc_retimer_pdata *retimer;
};

/**
 * struct intel_m10bmc - Intel MAX 10 BMC parent driver data structure
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

#endif /* __MFD_INTEL_M10_BMC_H */
