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

#define M10BMC_LEGACY_SYS_BASE	0x300400
#define M10BMC_SYS_BASE		0x300800
#define M10BMC_MEM_END		0x200000fc

/* Register offset of system registers */
#define NIOS2_FW_VERSION	0x0
#define M10BMC_MACADDR1		0x10
#define   M10BMC_MAC_BYTE4	GENMASK(7, 0)
#define   M10BMC_MAC_BYTE3	GENMASK(15, 8)
#define   M10BMC_MAC_BYTE2	GENMASK(23, 16)
#define   M10BMC_MAC_BYTE1	GENMASK(31, 24)
#define M10BMC_MACADDR2		0x14
#define   M10BMC_MAC_BYTE6	GENMASK(7, 0)
#define   M10BMC_MAC_BYTE5	GENMASK(15, 8)
#define   M10BMC_MAC_COUNT	GENMASK(23, 16)
#define M10BMC_TEST_REG		0x3c
#define M10BMC_BUILD_VER	0x68
#define M10BMC_VER_MAJOR_MSK	GENMASK(23, 16)
#define M10BMC_VER_PCB_INFO_MSK	GENMASK(31, 24)

/* PKVL related registers, in system register region */
#define PKVL_POLLING_CTRL		0x80
#define   POLLING_MODE			GENMASK(15, 0)
#define   PKVL_A_PRELOAD		BIT(16)
#define   PKVL_A_PRELOAD_TIMEOUT	BIT(17)
#define   PKVL_A_DATA_TOO_BIG		BIT(18)
#define   PKVL_A_HDR_CHECKSUM		BIT(20)
#define   PKVL_B_PRELOAD		BIT(24)
#define   PKVL_B_PRELOAD_TIMEOUT	BIT(25)
#define   PKVL_B_DATA_TOO_BIG		BIT(26)
#define   PKVL_B_HDR_CHECKSUM		BIT(28)
#define   PKVL_EEPROM_UPG_STATUS	GENMASK(31, 16)
#define PKVL_LINK_STATUS		0x164
#define PKVL_A_VERSION			0x254
#define PKVL_B_VERSION			0x258
#define   SERDES_VERSION		GENMASK(15, 0)
#define   SBUS_VERSION			GENMASK(31, 16)

#define PKVL_PRELOAD		(PKVL_A_PRELOAD | PKVL_B_PRELOAD)
#define PKVL_PRELOAD_TIMEOUT	(PKVL_A_PRELOAD_TIMEOUT |\
				 PKVL_B_PRELOAD_TIMEOUT)
#define PKVL_DATA_TOO_BIG	(PKVL_A_DATA_TOO_BIG | PKVL_B_DATA_TOO_BIG)
#define PKVL_HDR_CHECKSUM	(PKVL_A_HDR_CHECKSUM | PKVL_B_HDR_CHECKSUM)

#define PKVL_UPG_STATUS_MASK	(PKVL_PRELOAD | PKVL_PRELOAD_TIMEOUT |\
				 PKVL_DATA_TOO_BIG | PKVL_HDR_CHECKSUM)
#define PKVL_UPG_STATUS_GOOD	(PKVL_PRELOAD | PKVL_HDR_CHECKSUM)

/* interval 100ms and timeout 2s */
#define PKVL_EEPROM_LOAD_INTERVAL_US	(100 * 1000)
#define PKVL_EEPROM_LOAD_TIMEOUT_US	(2 * 1000 * 1000)

/* interval 100ms and timeout 30s */
#define PKVL_PRELOAD_INTERVAL_US	(100 * 1000)
#define PKVL_PRELOAD_TIMEOUT_US		(30 * 1000 * 1000)

/**
 * struct intel_m10bmc_platdata - Intel Max10 BMC MFD device platform data
 *
 * @pkvl_master: the device which connects to the pkvl retimer on max10.
 */
struct intel_m10bmc_platdata {
	struct device *pkvl_master;
};

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
/* subdev Parkvale Interface  */
struct intel_m10bmc_pkvl_pdata {
	struct device *pkvl_master;
};

/* M10BMC sub devices for both PAC N3000 & PAC D5005 */
/* subdev security engine */
#define INTEL_M10BMC_SEC_DRV_NAME	"m10bmc-secure"

#endif /* __INTEL_M10_BMC_H */
