/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header File for DFL driver and device API
 *
 * Copyright (C) 2020 Silicom Denmark A/S. All rights reserved.
 */

#ifndef __SILICOM_N5010_PHY_H
#define __SILICOM_N5010_PHY_H

int n5010_phy_module_info(struct net_device *netdev);
int n5010_phy_attach(struct device *dev, struct net_device *netdev,
		     bool (*update)(struct net_device *netdev), u64 port_num);
int n5010_phy_detach(struct net_device *netdev);

#endif
