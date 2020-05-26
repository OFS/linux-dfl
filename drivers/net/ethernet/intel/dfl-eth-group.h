/* SPDX-License-Identifier: GPL-2.0 */

/* Internal header file for FPGA DFL Ether Group Driver
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 */

#ifndef __DFL_ETH_GROUP_H__
#define __DFL_ETH_GROUP_H__

#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/rtnetlink.h>

/* Used when trying to find a virtual mii bus on a specific dfl device.
 * dev_name(dfl base device)-mii
 */
#define DFL_ETH_MII_ID_FMT "%s-mii"

struct eth_dev {
	struct dfl_eth_group *egroup;
	struct device *dev;
	int index;
	bool lw_mac;
	struct eth_com *phy;
	struct eth_com *mac;
	struct net_device *netdev;

	char phy_id[MII_BUS_ID_SIZE + 3];
};

struct eth_dev_ops {
	int (*lineside_init)(struct eth_dev *edev);
	void (*lineside_remove)(struct eth_dev *edev);
	int (*reset)(struct eth_dev *edev, bool en);
};

struct n3000_net_priv {
	struct eth_dev *edev;
};

static inline struct eth_dev *net_device_to_eth_dev(struct net_device *netdev)
{
	struct n3000_net_priv *priv = netdev_priv(netdev);

	return priv->edev;
}

struct stat_info {
	unsigned int addr;
	char string[ETH_GSTRING_LEN];
};

#define STAT_INFO(_addr, _string) \
	.addr = _addr, .string = _string,

int do_eth_com_write_reg(struct eth_com *ecom, bool add_feature,
			 u16 addr, u32 data);
int do_eth_com_read_reg(struct eth_com *ecom, bool add_feature,
			u16 addr, u32 *data);

#define eth_com_write_reg(ecom, addr, data)	\
	do_eth_com_write_reg(ecom, false, addr, data)

#define eth_com_read_reg(ecom, addr, data)	\
	do_eth_com_read_reg(ecom, false, addr, data)

#define eth_com_add_feat_write_reg(ecom, addr, data)	\
	do_eth_com_write_reg(ecom, true, addr, data)

#define eth_com_add_feat_read_reg(ecom, addr, data)	\
	do_eth_com_read_reg(ecom, true, addr, data)

u64 read_mac_stats(struct eth_com *ecom, unsigned int addr);

struct net_device *n3000_netdev_create(struct eth_dev *edev);
netdev_tx_t n3000_dummy_netdev_xmit(struct sk_buff *skb,
				    struct net_device *dev);

extern struct eth_dev_ops dfl_eth_dev_10g_ops;
extern struct eth_dev_ops dfl_eth_dev_25g_ops;
extern struct eth_dev_ops dfl_eth_dev_40g_ops;

#endif /* __DFL_ETH_GROUP_H__ */
