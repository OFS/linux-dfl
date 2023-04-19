/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Header file for FPGA Feature Driver
 *
 * Copyright (C) 2023 Intel Corp.
 *
 */

#ifndef __DFL_PRIV_FEAT_H
#define __DFL_PRIV_FEAT_H

/**
 * struct dfl_priv_feat - dfl feature private data
 *
 * @mgr: FPGA Feature platform device.
 * @region_list: linked list of FME's FPGA regions.
 * @bridge_list: linked list of FME's FPGA bridges.
 * @pdata: feature platform device's pdata.
 */
struct dfl_priv_feat {
	struct platform_device *mgr;
	struct list_head region_list;
	struct list_head bridge_list;
	struct dfl_feature_platform_data *pdata;
};

#endif /* __DFL_PRIV_FEAT_H */
