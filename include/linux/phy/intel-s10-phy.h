/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header File for Intel Stratix 10 Phy Driver.
 *
 * Copyright 2019-2020 Intel Corporation, Inc.
 */
#ifndef __INTEL_S10_PHY_H
#define __INTEL_S10_PHY_H

#define INTEL_S10_PHY_DRV_NAME	"intel-s10-phy"

/**
 * struct intel_s10_platform_data - Platform data of the Intel S10 Phy Driver
 * @csr_base:	Base address of Control & Status registers
 */
struct intel_s10_platform_data {
	void __iomem *csr_base;
	u32 phy_offset;
};

#endif /* __INTEL_S10_PHY_H */
