// SPDX-License-Identifier: GPL-2.0
/* DFL device driver for Ether Group private feature on Intel PAC (Programmable
 * Acceleration Card) N3000
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Xu Yilun <yilun.xu@intel.com>
 */
#include <linux/bitfield.h>
#include <linux/dfl.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/stddef.h>
#include <linux/types.h>

#include "dfl-eth-group.h"

struct dfl_eth_group {
	char name[32];
	struct device *dev;
	void __iomem *base;
	/* lock to protect register access of the ether group */
	struct mutex reg_lock;
	struct dfl_device *dfl_dev;
	unsigned int config;
	unsigned int direction;
	unsigned int group_id;
	unsigned int speed;
	unsigned int lw_mac;
	unsigned int num_edevs;
	struct eth_dev *edevs;
	struct eth_dev_ops *ops;
};

u64 read_mac_stats(struct eth_com *ecom, unsigned int addr)
{
	u32 data_l, data_h;

	if (eth_com_read_reg(ecom, addr, &data_l) ||
	    eth_com_read_reg(ecom, addr + 1, &data_h))
		return 0xffffffffffffffffULL;

	return data_l + ((u64)data_h << 32);
}

netdev_tx_t n3000_dummy_netdev_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	kfree_skb(skb);
	net_warn_ratelimited("%s(): Dropping skb.\n", __func__);
	return NETDEV_TX_OK;
}

static void n3000_netdev_setup(struct net_device *netdev)
{
	netdev->features = 0;
	netdev->hard_header_len = 0;
	netdev->priv_flags |= IFF_NO_QUEUE;
	netdev->needs_free_netdev = true;
	netdev->min_mtu = 0;
	netdev->max_mtu = ETH_MAX_MTU;
}

struct net_device *n3000_netdev_create(struct eth_dev *edev)
{
	struct dfl_eth_group *egroup = edev->egroup;
	struct n3000_net_priv *priv;
	struct net_device *netdev;
	char name[IFNAMSIZ];

	/* The name of n3000 network device is using this format "npacAgBlC"
	 *
	 * A is the unique ethdev index
	 * B is the group id of this ETH Group.
	 * C is the PHY/MAC link index for Line side ethernet group.
	 */
	snprintf(name, IFNAMSIZ, "npac%%dg%ul%u",
		 egroup->group_id, edev->index);

	netdev = alloc_netdev(sizeof(*priv), name, NET_NAME_UNKNOWN,
			      n3000_netdev_setup);
	if (!netdev)
		return NULL;

	priv = netdev_priv(netdev);
	priv->edev = edev;
	SET_NETDEV_DEV(netdev, egroup->dev);

	return netdev;
}

enum n3000_eth_cfg {
	ETH_CONFIG_8x10G,
	ETH_CONFIG_4x25G,
	ETH_CONFIG_2x1x25G,
	ETH_CONFIG_4x25G_2x25G,
	ETH_CONFIG_2x2x25G,
	ETH_CONFIG_MAX
};

#define N3000_EDEV_MAX 8

static int phy_addr_table[ETH_CONFIG_MAX][N3000_EDEV_MAX] = {
	/* 8x10G configuration
	 *
	 *    [retimer_dev]   <------->   [eth_dev]
	 *	  0			   0
	 *	  1			   1
	 *	  2			   2
	 *	  3			   3
	 *	  4			   4
	 *	  5			   5
	 *	  6			   6
	 *	  7			   7
	 */
	[ETH_CONFIG_8x10G] = {0, 1, 2, 3, 4, 5, 6, 7},

	/* 4x25G and 4x25G_2x25G configuration
	 *
	 *    [retimer_dev]   <------->   [eth_dev]
	 *	  0			   0
	 *	  1			   1
	 *	  2			   2
	 *	  3			   3
	 *	  4
	 *	  5
	 *	  6
	 *	  7
	 */
	[ETH_CONFIG_4x25G] = {0, 1, 2, 3, -1, -1, -1, -1},
	[ETH_CONFIG_4x25G_2x25G] = {0, 1, 2, 3, -1, -1, -1, -1},

	/* 2x1x25G configuration
	 *
	 *    [retimer_dev]   <------->   [eth_dev]
	 *        0                      0
	 *        1
	 *        2
	 *        3
	 *        4                      1
	 *        5
	 *        6
	 *        7
	 */
	[ETH_CONFIG_2x1x25G] = {0, 4, -1, -1, -1, -1, -1, -1},

	/* 2x2x25G configuration
	 *
	 *    [retimer_dev]   <------->   [eth_dev]
	 *	  0			   0
	 *	  1			   1
	 *	  2
	 *	  3
	 *	  4			   2
	 *	  5			   3
	 *	  6
	 *	  7
	 */
	[ETH_CONFIG_2x2x25G] = {0, 1, 4, 5, -1, -1, -1, -1},
};

#define eth_group_for_each_dev(edev, egp) \
	for ((edev) = (egp)->edevs; (edev) < (egp)->edevs + (egp)->num_edevs; \
	     (edev)++)

#define eth_group_reverse_each_dev(edev, egp) \
	for ((edev)--; (edev) >= (egp)->edevs; (edev)--)

static struct mii_bus *eth_group_get_phy_bus(struct dfl_eth_group *egroup)
{
	char mii_name[MII_BUS_ID_SIZE];
	struct device *base_dev;
	struct mii_bus *bus;

	base_dev = dfl_dev_get_base_dev(egroup->dfl_dev);
	if (!base_dev)
		return ERR_PTR(-ENODEV);

	snprintf(mii_name, MII_BUS_ID_SIZE, DFL_ETH_MII_ID_FMT,
		 dev_name(base_dev));

	bus = mdio_find_bus(mii_name);
	if (!bus)
		return ERR_PTR(-EPROBE_DEFER);

	return bus;
}

static int eth_dev_get_phy_id(struct eth_dev *edev, struct mii_bus *bus)
{
	struct dfl_eth_group *egroup = edev->egroup;
	struct phy_device *phydev;
	int phyaddr;

	phyaddr = phy_addr_table[egroup->config][edev->index];
	if (phyaddr < 0)
		return -ENODEV;

	phydev = mdiobus_get_phy(bus, phyaddr);
	if (!phydev) {
		dev_err(egroup->dev, "fail to get phydev\n");
		return -EPROBE_DEFER;
	}

	strncpy(edev->phy_id, phydev_name(phydev), MII_BUS_ID_SIZE + 3);
	edev->phy_id[MII_BUS_ID_SIZE + 2] = '\0';

	return 0;
}

static int init_lineside_eth_devs(struct dfl_eth_group *egroup,
				  struct mii_bus *phy_bus)
{
	struct eth_dev *edev;
	int ret = 0;

	if (!egroup->ops->lineside_init)
		return -ENODEV;

	eth_group_for_each_dev(edev, egroup) {
		ret = eth_dev_get_phy_id(edev, phy_bus);
		if (ret)
			break;

		ret = egroup->ops->lineside_init(edev);
		if (ret)
			break;
	}

	if (!ret)
		return 0;

	dev_err(egroup->dev, "failed to init lineside edev %d", edev->index);

	if (egroup->ops->lineside_remove)
		eth_group_reverse_each_dev(edev, egroup)
			egroup->ops->lineside_remove(edev);

	return ret;
}

static void remove_lineside_eth_devs(struct dfl_eth_group *egroup)
{
	struct eth_dev *edev;

	if (!egroup->ops->lineside_remove)
		return;

	eth_group_for_each_dev(edev, egroup)
		egroup->ops->lineside_remove(edev);
}

#define ETH_GROUP_INFO		0x8
#define LIGHT_WEIGHT_MAC	BIT_ULL(25)
#define INFO_DIRECTION		BIT_ULL(24)
#define INFO_SPEED		GENMASK_ULL(23, 16)
#define INFO_PHY_NUM		GENMASK_ULL(15, 8)
#define INFO_GROUP_ID		GENMASK_ULL(7, 0)

#define ETH_GROUP_CTRL		0x10
#define CTRL_CMD		GENMASK_ULL(63, 62)
#define CMD_NOP			0
#define CMD_RD			1
#define CMD_WR			2
#define CTRL_DEV_SELECT		GENMASK_ULL(53, 49)
#define CTRL_FEAT_SELECT	BIT_ULL(48)
#define SELECT_IP		0
#define SELECT_FEAT		1
#define CTRL_ADDR		GENMASK_ULL(47, 32)
#define CTRL_WR_DATA		GENMASK_ULL(31, 0)

#define ETH_GROUP_STAT		0x18
#define STAT_RW_VAL		BIT_ULL(32)
#define STAT_RD_DATA		GENMASK_ULL(31, 0)

enum ecom_type {
	ETH_GROUP_PHY	= 1,
	ETH_GROUP_MAC,
	ETH_GROUP_ETHER
};

struct eth_com {
	struct dfl_eth_group *egroup;
	unsigned int type;
	u8 select;
};

static const char *eth_com_type_string(enum ecom_type type)
{
	switch (type) {
	case ETH_GROUP_PHY:
		return "phy";
	case ETH_GROUP_MAC:
		return "mac";
	case ETH_GROUP_ETHER:
		return "ethernet wrapper";
	default:
		return "unknown";
	}
}

#define eth_com_base(com)	((com)->egroup->base)
#define eth_com_dev(com)	((com)->egroup->dev)

#define RW_VAL_INVL		1 /* us */
#define RW_VAL_POLL_TIMEOUT	10 /* us */

static int __do_eth_com_write_reg(struct eth_com *ecom, bool add_feature,
				  u16 addr, u32 data)
{
	void __iomem *base = eth_com_base(ecom);
	struct device *dev = eth_com_dev(ecom);
	u64 v = 0;

	dev_dbg(dev, "%s [%s] select 0x%x add_feat %d addr 0x%x data 0x%x\n",
		__func__, eth_com_type_string(ecom->type),
		ecom->select, add_feature, addr, data);

	/* only PHY has additional feature registers */
	if (add_feature && ecom->type != ETH_GROUP_PHY)
		return -EINVAL;

	v |= FIELD_PREP(CTRL_CMD, CMD_WR);
	v |= FIELD_PREP(CTRL_DEV_SELECT, ecom->select);
	v |= FIELD_PREP(CTRL_ADDR, addr);
	v |= FIELD_PREP(CTRL_WR_DATA, data);
	v |= FIELD_PREP(CTRL_FEAT_SELECT, !!add_feature);

	writeq(v, base + ETH_GROUP_CTRL);

	if (readq_poll_timeout(base + ETH_GROUP_STAT, v, v & STAT_RW_VAL,
			       RW_VAL_INVL, RW_VAL_POLL_TIMEOUT))
		return -ETIMEDOUT;

	return 0;
}

static int __do_eth_com_read_reg(struct eth_com *ecom, bool add_feature,
				 u16 addr, u32 *data)
{
	void __iomem *base = eth_com_base(ecom);
	struct device *dev = eth_com_dev(ecom);
	u64 v = 0;

	dev_dbg(dev, "%s [%s] select %x add_feat %d addr %x\n",
		__func__, eth_com_type_string(ecom->type),
		ecom->select, add_feature, addr);

	/* only PHY has additional feature registers */
	if (add_feature && ecom->type != ETH_GROUP_PHY)
		return -EINVAL;

	v |= FIELD_PREP(CTRL_CMD, CMD_RD);
	v |= FIELD_PREP(CTRL_DEV_SELECT, ecom->select);
	v |= FIELD_PREP(CTRL_ADDR, addr);
	v |= FIELD_PREP(CTRL_FEAT_SELECT, !!add_feature);

	writeq(v, base + ETH_GROUP_CTRL);

	if (readq_poll_timeout(base + ETH_GROUP_STAT, v, v & STAT_RW_VAL,
			       RW_VAL_INVL, RW_VAL_POLL_TIMEOUT))
		return -ETIMEDOUT;

	*data = FIELD_GET(STAT_RD_DATA, v);

	return 0;
}

int do_eth_com_write_reg(struct eth_com *ecom, bool add_feature,
			 u16 addr, u32 data)
{
	int ret;

	mutex_lock(&ecom->egroup->reg_lock);
	ret = __do_eth_com_write_reg(ecom, add_feature, addr, data);
	mutex_unlock(&ecom->egroup->reg_lock);
	return ret;
}

int do_eth_com_read_reg(struct eth_com *ecom, bool add_feature,
			u16 addr, u32 *data)
{
	int ret;

	mutex_lock(&ecom->egroup->reg_lock);
	ret = __do_eth_com_read_reg(ecom, add_feature, addr, data);
	mutex_unlock(&ecom->egroup->reg_lock);
	return ret;
}

static struct eth_com *
eth_com_create(struct dfl_eth_group *egroup, enum ecom_type type,
	       unsigned int link_idx)
{
	struct eth_com *ecom;

	ecom = devm_kzalloc(egroup->dev, sizeof(*ecom), GFP_KERNEL);
	if (!ecom)
		return ERR_PTR(-ENOMEM);

	ecom->egroup = egroup;
	ecom->type = type;

	if (type == ETH_GROUP_PHY)
		ecom->select = link_idx * 2 + 2;
	else if (type == ETH_GROUP_MAC)
		ecom->select = link_idx * 2 + 3;
	else if (type == ETH_GROUP_ETHER)
		ecom->select = 0;

	return ecom;
}

static int init_eth_dev(struct eth_dev *edev, struct dfl_eth_group *egroup,
			unsigned int link_idx)
{
	edev->egroup = egroup;
	edev->dev = egroup->dev;
	edev->index = link_idx;
	edev->lw_mac = !!egroup->lw_mac;
	edev->phy = eth_com_create(egroup, ETH_GROUP_PHY, link_idx);
	if (IS_ERR(edev->phy))
		return PTR_ERR(edev->phy);

	edev->mac = eth_com_create(egroup, ETH_GROUP_MAC, link_idx);
	if (IS_ERR(edev->mac))
		return PTR_ERR(edev->mac);

	return 0;
}

static int eth_devs_init(struct dfl_eth_group *egroup)
{
	int ret, i;

	egroup->edevs = devm_kcalloc(egroup->dev, egroup->num_edevs,
				     sizeof(*egroup->edevs), GFP_KERNEL);
	if (!egroup->edevs)
		return -ENOMEM;

	for (i = 0; i < egroup->num_edevs; i++) {
		ret = init_eth_dev(&egroup->edevs[i], egroup, i);
		if (ret)
			return ret;
	}

	return 0;
}

static int eth_group_setup(struct dfl_eth_group *egroup)
{
	int net_cfg, ret;
	u64 v;

	/* read parameters of this ethernet components group */
	v = readq(egroup->base + ETH_GROUP_INFO);

	egroup->direction = FIELD_GET(INFO_DIRECTION, v);
	egroup->speed = FIELD_GET(INFO_SPEED, v);
	egroup->num_edevs = FIELD_GET(INFO_PHY_NUM, v);
	egroup->group_id = FIELD_GET(INFO_GROUP_ID, v);
	egroup->lw_mac = FIELD_GET(LIGHT_WEIGHT_MAC, v);

	net_cfg = dfl_dev_get_vendor_net_cfg(egroup->dfl_dev);
	if (net_cfg < 0)
		return -EINVAL;

	egroup->config = (unsigned int)net_cfg;

	ret = eth_devs_init(egroup);
	if (ret)
		return ret;

	switch (egroup->speed) {
	case 10:
		egroup->ops = &dfl_eth_dev_10g_ops;
		break;
	case 25:
		egroup->ops = &dfl_eth_dev_25g_ops;
		break;
	case 40:
		egroup->ops = &dfl_eth_dev_40g_ops;
		break;
	}

	mutex_init(&egroup->reg_lock);

	return 0;
}

static void eth_group_destroy(struct dfl_eth_group *egroup)
{
	mutex_destroy(&egroup->reg_lock);
}

static void eth_group_devs_disable(struct dfl_eth_group *egroup)
{
	struct eth_dev *edev;

	eth_group_for_each_dev(edev, egroup)
		egroup->ops->reset(edev, true);
}

static int eth_group_devs_enable(struct dfl_eth_group *egroup)
{
	struct eth_dev *edev;
	int ret;

	eth_group_for_each_dev(edev, egroup) {
		ret = egroup->ops->reset(edev, false);
		if (ret) {
			dev_err(egroup->dev, "fail to enable edev%d\n",
				edev->index);
			eth_group_devs_disable(egroup);
			return ret;
		}
	}

	return 0;
}

static int dfl_eth_group_line_side_init(struct dfl_eth_group *egroup)
{
	struct mii_bus *phy_bus;
	int ret;

	if (!egroup->ops || !egroup->ops->reset ||
	    !egroup->ops->lineside_init || !egroup->ops->lineside_remove)
		return -EINVAL;

	eth_group_devs_disable(egroup);

	phy_bus = eth_group_get_phy_bus(egroup);
	if (IS_ERR(phy_bus))
		return PTR_ERR(phy_bus);

	ret = init_lineside_eth_devs(egroup, phy_bus);
	put_device(&phy_bus->dev);

	return ret;
}

static void dfl_eth_group_line_side_uinit(struct dfl_eth_group *egroup)
{
	remove_lineside_eth_devs(egroup);
}

static int dfl_eth_group_host_side_init(struct dfl_eth_group *egroup)
{
	if (!egroup->ops || !egroup->ops->reset)
		return -EINVAL;

	return eth_group_devs_enable(egroup);
}

static int dfl_eth_group_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct dfl_eth_group *egroup;
	int ret;

	egroup = devm_kzalloc(dev, sizeof(*egroup), GFP_KERNEL);
	if (!egroup)
		return -ENOMEM;

	dev_set_drvdata(&dfl_dev->dev, egroup);

	egroup->dev = dev;
	egroup->dfl_dev = dfl_dev;

	egroup->base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (IS_ERR(egroup->base)) {
		dev_err(dev, "get mem resource fail!\n");
		return PTR_ERR(egroup->base);
	}

	ret = eth_group_setup(egroup);
	if (ret)
		return ret;

	if (egroup->direction == 1)
		ret = dfl_eth_group_line_side_init(egroup);
	else
		ret = dfl_eth_group_host_side_init(egroup);

	if (!ret)
		return 0;

	eth_group_destroy(egroup);

	return ret;
}

static void dfl_eth_group_remove(struct dfl_device *dfl_dev)
{
	struct dfl_eth_group *egroup = dev_get_drvdata(&dfl_dev->dev);

	if (egroup->direction == 1)
		dfl_eth_group_line_side_uinit(egroup);

	eth_group_devs_disable(egroup);
	eth_group_destroy(egroup);
}

#define FME_FEATURE_ID_ETH_GROUP	0x10

static const struct dfl_device_id dfl_eth_group_ids[] = {
	{ FME_ID, FME_FEATURE_ID_ETH_GROUP },
	{ }
};

static struct dfl_driver dfl_eth_group_driver = {
	.drv	= {
		.name       = "dfl-eth-group",
	},
	.id_table = dfl_eth_group_ids,
	.probe   = dfl_eth_group_probe,
	.remove  = dfl_eth_group_remove,
};

module_dfl_driver(dfl_eth_group_driver);

MODULE_DEVICE_TABLE(dfl, dfl_eth_group_ids);
MODULE_DESCRIPTION("DFL ether group driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
