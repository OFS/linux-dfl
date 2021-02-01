// SPDX-License-Identifier: GPL-2.0

/* Silicom(R) Low Latency 100G Network Driver
 *
 * Copyright (C) 2020 Silicom Denmark. All rights reserved.
 */

#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/dfl.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/timer.h>
#include <linux/uaccess.h>

#include "n5010-phy.h"

#define CAPABILITY_OFFSET	0x08
#define CAP_AVAILABLE_RATES	GENMASK_ULL(7, 0)
#define CAP_CONTAINS_PCS	GENMASK_ULL(15, 8)
#define CAP_CONTAINS_FEC	GENMASK_ULL(23, 16)
#define CAP_PORT_CNT		GENMASK_ULL(43, 40)
#define CAP_RATE_1G		BIT_ULL(0)
#define CAP_RATE_10G		BIT_ULL(1)
#define CAP_RATE_25G		BIT_ULL(2)
#define CAP_RATE_40G		BIT_ULL(3)
#define CAP_RATE_50G		BIT_ULL(4)
#define CAP_RATE_100G		BIT_ULL(5)
#define CAP_RATE_200G		BIT_ULL(6)
#define CAP_RATE_400G		BIT_ULL(7)

#define MB_MAC_OFFSET		0x28
#define MB_FEC_OFFSET		0x68
#define MB_PHY_OFFSET		0xa8
#define MB_PORT_SIZE            0x10

#define PHY_BASE_OFF		0x2000
#define PHY_RX_SER_LOOP_BACK	0x4e1

#define FEC_RX_STATUS		0x180
#define FEC_RX_STATUS_LINK	0x0ULL
#define FEC_RX_STATUS_LINK_NO	0x3ULL

#define MAC_TX_SRC_ADDR_LO	0x40c
#define MAC_TX_SRC_ADDR_HI	0x40d
#define MAC_RX_MTU		0x506
#define MAC_MAX_MTU		9600

#define ILL_100G_TX_STATS_CLR	0x845
#define ILL_100G_RX_STATS_CLR	0x945
#define ILL_100G_LPBK_OFF	0x313
#define ILL_100G_LPBK_EN_VAL	0xffff

#define STATS_CLR_INT_US		1
#define STATS_CLR_INT_TIMEOUT_US	1000

struct n5010_hssi_ops_params {
	struct stat_info *stats;
	u32 num_stats;
	u32 tx_clr_off;
	u32 rx_clr_off;
};

struct n5010_hssi_regmaps {
	struct regmap *regmap;
};

struct n5010_hssi_netdata {
	struct dfl_device *dfl_dev;
	struct regmap *regmap_mac;
	struct regmap *regmap_fec;
	struct regmap *regmap_phy;
	u32 link_status;
	const struct n5010_hssi_ops_params *ops_params;
};

struct n5010_hssi_drvdata {
	struct dfl_device *dfl_dev;
	void __iomem *base;
	u64  port_cnt;
	struct net_device *netdev[];
};

static bool n5010_hssi_update_link(struct net_device *netdev)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);
	u32 link_status = FEC_RX_STATUS_LINK_NO;

	regmap_read(npriv->regmap_fec, FEC_RX_STATUS, &link_status);

	return link_status == FEC_RX_STATUS_LINK;
}

static int netdev_open(struct net_device *netdev)
{
	if (netdev->phydev)
		phy_start(netdev->phydev);

	return 0;
}

static int netdev_stop(struct net_device *netdev)
{
	if (netdev->phydev)
		phy_stop(netdev->phydev);

	return 0;
}

static int netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);

	netdev->mtu = new_mtu;

	return regmap_write(npriv->regmap_mac, MAC_RX_MTU, new_mtu);
}

static int netdev_set_features(struct net_device *netdev,
			       netdev_features_t features)
{
	return 0;
}

static int netdev_set_mac_address(struct net_device *netdev, void *p)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);
	struct sockaddr *addr = p;
	u32 mac_part1, mac_part2;
	int ret;

	memcpy(netdev->dev_addr, addr->sa_data, ETH_ALEN);

	mac_part1 = (addr->sa_data[0] << 8) | addr->sa_data[1];
	mac_part2 = (addr->sa_data[2] << 24) | (addr->sa_data[3] << 16) |
		    (addr->sa_data[4] << 8) | addr->sa_data[5];

	ret = regmap_write(npriv->regmap_mac, MAC_TX_SRC_ADDR_HI, mac_part1);
	if (ret)
		return ret;

	return regmap_write(npriv->regmap_mac, MAC_TX_SRC_ADDR_LO, mac_part2);
}

static netdev_tx_t netdev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	kfree_skb(skb);

	return NETDEV_TX_OK;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open = netdev_open,
	.ndo_stop = netdev_stop,
	.ndo_start_xmit = netdev_xmit,
	.ndo_change_mtu = netdev_change_mtu,
	.ndo_set_features = netdev_set_features,
	.ndo_set_mac_address = netdev_set_mac_address,
};

struct stat_info {
	unsigned int addr;
	char string[ETH_GSTRING_LEN];
};

#define STAT_INFO(_addr, _string) \
	.addr = _addr, .string = _string,

static void ethtool_get_strings(struct net_device *netdev, u32 stringset,
				u8 *s)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);
	unsigned int i, stats_num = 0;
	struct stat_info *stat;

	if (stringset != ETH_SS_STATS)
		return;

	stat = npriv->ops_params->stats;
	stats_num = npriv->ops_params->num_stats;

	for (i = 0; i < stats_num; i++, s += ETH_GSTRING_LEN)
		memcpy(s, stat[i].string, ETH_GSTRING_LEN);
}

static int ethtool_get_sset_count(struct net_device *netdev, int stringset)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);

	if (stringset == ETH_SS_STATS)
		return npriv->ops_params->num_stats;

	return 0;
}

static u64 read_mac_stat(struct regmap *regmap, unsigned int addr)
{
	u32 data_l, data_h;

	regmap_read(regmap, addr, &data_l);
	regmap_read(regmap, addr + 1, &data_h);

	return data_l + ((u64)data_h << 32);
}

static int ethtool_reset(struct net_device *netdev, u32 *flags)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);
	struct regmap *regmap = npriv->regmap_mac;
	u32 reg, val;
	int ret;

	if (*flags | ETH_RESET_MGMT) {
		reg = npriv->ops_params->tx_clr_off;

		ret = regmap_write(regmap, reg, 1);
		if (ret)
			return ret;

		ret = regmap_write(regmap, reg, 0);
		if (ret)
			return ret;

		ret = regmap_read_poll_timeout(regmap, reg, val, (val & 1) == 0,
					       STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);
		if (ret) {
			dev_err(&netdev->dev, "failed to clear tx stats\n");
			return ret;
		}

		reg = npriv->ops_params->rx_clr_off;

		ret = regmap_write(regmap, reg, 1);
		if (ret)
			return ret;

		ret = regmap_write(regmap, reg, 0);
		if (ret)
			return ret;

		ret = regmap_read_poll_timeout(regmap, reg, val, (val & 1) == 0,
					       STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);
		if (ret) {
			dev_err(&netdev->dev, "failed to clear rx stats\n");
			return ret;
		}
	}

	return 0;
}

static void ethtool_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct n5010_hssi_netdata *npriv = netdev_priv(netdev);
	unsigned int i, stats_num = npriv->ops_params->num_stats;
	struct stat_info *stat = npriv->ops_params->stats;

	for (i = 0; i < stats_num; i++)
		data[i] = read_mac_stat(npriv->regmap_mac, stat[i].addr);
}

static int ethtool_module_info(struct net_device *netdev,
			       struct ethtool_modinfo *modinfo)
{
	return n5010_phy_module_info(netdev);
}

static const struct ethtool_ops ethtool_ops = {
	.get_strings = ethtool_get_strings,
	.get_sset_count = ethtool_get_sset_count,
	.get_ethtool_stats = ethtool_get_stats,
	.get_link = ethtool_op_get_link,
	.get_module_info = ethtool_module_info,
	.reset = ethtool_reset,
};

static struct stat_info stats_100g[] = {
	/* tx statistics */
	{STAT_INFO(0x800, "tx_fragments")},
	{STAT_INFO(0x802, "tx_jabbers")},
	{STAT_INFO(0x804, "tx_crcerr")},
	{STAT_INFO(0x806, "tx_crcerr_sizeok")},
	{STAT_INFO(0x808, "tx_mcast_data_err")},
	{STAT_INFO(0x80a, "tx_bcast_data_err")},
	{STAT_INFO(0x80c, "tx_ucast_data_err")},
	{STAT_INFO(0x80e, "tx_mcast_ctrl_err")},
	{STAT_INFO(0x810, "tx_bcast_ctrl_err")},
	{STAT_INFO(0x812, "tx_ucast_ctrl_err")},
	{STAT_INFO(0x814, "tx_pause_err")},
	{STAT_INFO(0x816, "tx_64b")},
	{STAT_INFO(0x818, "tx_65to127b")},
	{STAT_INFO(0x81a, "tx_128to255b")},
	{STAT_INFO(0x81c, "tx_256to511b")},
	{STAT_INFO(0x81e, "tx_512to1023b")},
	{STAT_INFO(0x820, "tx_1024to1518b")},
	{STAT_INFO(0x822, "tx_1519tomaxb")},
	{STAT_INFO(0x824, "tx_oversize")},
	{STAT_INFO(0x836, "tx_st")},
	{STAT_INFO(0x826, "tx_mcast_data_ok")},
	{STAT_INFO(0x828, "tx_bcast_data_ok")},
	{STAT_INFO(0x82a, "tx_ucast_data_ok")},
	{STAT_INFO(0x82c, "tx_mcast_ctrl_ok")},
	{STAT_INFO(0x82e, "tx_bcast_ctrl_ok")},
	{STAT_INFO(0x830, "tx_ucast_ctrl_ok")},
	{STAT_INFO(0x832, "tx_pause")},
	{STAT_INFO(0x860, "tx_payload_octets_ok")},
	{STAT_INFO(0x862, "tx_frame_octets_ok")},

	/* rx statistics */
	{STAT_INFO(0x900, "rx_fragments")},
	{STAT_INFO(0x902, "rx_jabbers")},
	{STAT_INFO(0x904, "rx_crcerr")},
	{STAT_INFO(0x906, "rx_crcerr_sizeok")},
	{STAT_INFO(0x908, "rx_mcast_data_err")},
	{STAT_INFO(0x90a, "rx_bcast_data_err")},
	{STAT_INFO(0x90c, "rx_ucast_data_err")},
	{STAT_INFO(0x90e, "rx_mcast_ctrl_err")},
	{STAT_INFO(0x910, "rx_bcast_ctrl_err")},
	{STAT_INFO(0x912, "rx_ucast_ctrl_err")},
	{STAT_INFO(0x914, "rx_pause_err")},
	{STAT_INFO(0x916, "rx_64b")},
	{STAT_INFO(0x918, "rx_65to127b")},
	{STAT_INFO(0x91a, "rx_128to255b")},
	{STAT_INFO(0x91c, "rx_256to511b")},
	{STAT_INFO(0x91e, "rx_512to1023b")},
	{STAT_INFO(0x920, "rx_1024to1518b")},
	{STAT_INFO(0x922, "rx_1519tomaxb")},
	{STAT_INFO(0x924, "rx_oversize")},
	{STAT_INFO(0x936, "rx_st")},
	{STAT_INFO(0x926, "rx_mcast_data_ok")},
	{STAT_INFO(0x928, "rx_bcast_data_ok")},
	{STAT_INFO(0x92a, "rx_ucast_data_ok")},
	{STAT_INFO(0x92c, "rx_mcast_ctrl_ok")},
	{STAT_INFO(0x92e, "rx_bcast_ctrl_ok")},
	{STAT_INFO(0x930, "rx_ucast_ctrl_ok")},
	{STAT_INFO(0x932, "rx_pause")},
	{STAT_INFO(0x960, "rx_payload_octets_ok")},
	{STAT_INFO(0x962, "rx_frame_octets_ok")},
};

static const struct n5010_hssi_ops_params n5010_100g_params = {
	.stats = stats_100g,
	.num_stats = ARRAY_SIZE(stats_100g),
	.tx_clr_off = ILL_100G_TX_STATS_CLR,
	.rx_clr_off = ILL_100G_RX_STATS_CLR,
};

static void n5010_hssi_init_netdev(struct net_device *netdev)
{
	netdev->ethtool_ops = &ethtool_ops;
	netdev->netdev_ops = &netdev_ops;
	netdev->features = 0;
	netdev->hard_header_len = 0;
	netdev->priv_flags |= IFF_NO_QUEUE;
	netdev->max_mtu = MAC_MAX_MTU;
	netdev->needs_free_netdev  = true;

	ether_setup(netdev);
}

enum n5010_hssi_regmap {
	regmap_mac,
	regmap_fec,
	regmap_phy,
};

#ifndef devm_regmap_init_indirect_register
struct regmap *devm_regmap_init_indirect_register(struct device *dev,
						  void __iomem *base,
						  struct regmap_config *cfg);
#endif

static struct regmap *n5010_hssi_create_regmap(struct n5010_hssi_drvdata *priv,
					       u64 port,
					       enum n5010_hssi_regmap type)
{
	void __iomem *base = priv->base + port * MB_PORT_SIZE;
	struct device *dev = &priv->dfl_dev->dev;
	struct regmap_config cfg = {0};
	char regmap_name[20];

	switch (type) {
	case regmap_mac:
		sprintf(regmap_name, "n5010_hssi_mac%llu", port);
		base += MB_MAC_OFFSET;
		cfg.val_bits = 32;
		cfg.max_register = 0xbbf;
		break;
	case regmap_fec:
		sprintf(regmap_name, "n5010_hssi_fec%llu", port);
		base += MB_FEC_OFFSET;
		cfg.val_bits = 8;
		cfg.max_register = 0x29c;
		break;
	case regmap_phy:
		sprintf(regmap_name, "n5010_hssi_phy%llu", port);
		base += MB_PHY_OFFSET;
		cfg.val_bits = 8;
		cfg.max_register = 0x40144;
		break;
	}

	cfg.name = regmap_name;
	cfg.reg_bits = 32;

	return devm_regmap_init_indirect_register(dev, base, &cfg);
}

static int n5010_hssi_create_netdev(struct n5010_hssi_drvdata *priv,
				    struct device *phy, u64 port)
{
	struct device *dev = &priv->dfl_dev->dev;
	struct n5010_hssi_netdata *npriv;
	struct net_device *netdev;
	int err = -ENOMEM;
	u32 flags;

	netdev = alloc_netdev(sizeof(struct n5010_hssi_netdata),
			      "n5010_hssi%d", NET_NAME_UNKNOWN,
			      n5010_hssi_init_netdev);
	priv->netdev[port] = netdev;

	if (!netdev)
		return -ENOMEM;

	npriv = netdev_priv(netdev);

	npriv->dfl_dev = priv->dfl_dev;

	npriv->regmap_mac = n5010_hssi_create_regmap(priv, port, regmap_mac);
	if (!npriv->regmap_mac)
		goto err_unreg_netdev;

	npriv->regmap_fec = n5010_hssi_create_regmap(priv, port, regmap_fec);
	if (!npriv->regmap_fec)
		goto err_unreg_netdev;

	npriv->regmap_phy = n5010_hssi_create_regmap(priv, port, regmap_phy);
	if (!npriv->regmap_phy)
		goto err_unreg_netdev;

	npriv->ops_params = &n5010_100g_params;

	SET_NETDEV_DEV(netdev, dev);

	flags = ETH_RESET_MGMT;

	npriv->link_status = FEC_RX_STATUS_LINK_NO;

	err = ethtool_reset(netdev, &flags);
	if (err) {
		dev_err(dev, "failed to reset MGMT %s: %d", netdev->name, err);
		goto err_unreg_netdev;
	}

	err = register_netdev(netdev);
	if (err) {
		dev_err(dev, "failed to register %s: %d", netdev->name, err);
		goto err_unreg_netdev;
	}

	err = n5010_phy_attach(phy, netdev, n5010_hssi_update_link, port);
	if (err)
		goto err_unreg_netdev;

	return 0;

err_unreg_netdev:
	unregister_netdev(netdev);

	return err;
}

static int n5010_match_phy_dev(struct device *dev, void *data)
{
	return dev->driver && !strcmp(dev->driver->name, "n5010bmc-phy");
}

static int n5010_match_phy_master(struct device *dev, const void *data)
{
	struct dfl_device *dfl_dev = (void *)data;
	struct device *base_dev = dfl_dev_get_base_dev(dfl_dev);

	/* look trace device tree until a direct dfl-device is found */
	do {
		if (!dev->bus)
			continue;

		if (!strcmp(dev->bus->name, "dfl"))
			break;

		if (!dev->parent)
			return 0;
	} while ((dev = dev->parent));

	if (!dev)
		return 0;

	/* compare the base (pci) device of the spi controller with the base
	 * (pci) device of the n5010-hssi device
	 */
	return dfl_dev_get_base_dev(to_dfl_dev(dev)) == base_dev;
}

static int n5010_hssi_probe(struct dfl_device *dfl_dev)
{
	struct device *phy_master, *phy_dev;
	struct device *dev = &dfl_dev->dev;
	struct n5010_hssi_drvdata *priv;
	u64 val, port_cnt, port;
	void __iomem *base;
	u64 priv_size;
	int ret = 0;

	/* find the spi controller from this pci device */
	phy_master = bus_find_device(&spi_bus_type, NULL, dfl_dev,
				     n5010_match_phy_master);
	if (!phy_master) {
		dev_info(dev, "phy master not found; deferring probe\n");
		return -EPROBE_DEFER;
	}

	/* find the spi slave matching the n5010-phy driver */
	phy_dev = device_find_child(phy_master, dfl_dev,
				    n5010_match_phy_dev);
	if (!phy_dev) {
		dev_info(dev, "phy slave not found; deferring probe\n");
		ret = -EPROBE_DEFER;
		goto err_phy_master;
	}

	base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (IS_ERR(base)) {
		ret = PTR_ERR(base);
		goto err_phy_dev;
	}

	val = readq(base + CAPABILITY_OFFSET);
	port_cnt =  FIELD_GET(CAP_PORT_CNT, val);
	priv_size = sizeof(*priv) + port_cnt * sizeof(void *);

	priv = devm_kzalloc(dev, priv_size, GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto err_phy_dev;
	}

	dev_set_drvdata(dev, priv);

	priv->dfl_dev = dfl_dev;
	priv->port_cnt = port_cnt;
	priv->base = base;

	for (port = 0; port < priv->port_cnt; port++) {
		ret = n5010_hssi_create_netdev(priv, phy_dev, port);
		if (ret)
			goto err_phy_dev;
	}

err_phy_dev:
	put_device(phy_dev);
err_phy_master:
	put_device(phy_master);

	return ret;
}

static void n5010_hssi_remove(struct dfl_device *dfl_dev)
{
	struct n5010_hssi_drvdata *priv = dev_get_drvdata(&dfl_dev->dev);
	u64 port;

	for (port = 0; port < priv->port_cnt; port++) {
		n5010_phy_detach(priv->netdev[port]);
		unregister_netdev(priv->netdev[port]);
	}
}

#define FME_FEATURE_ID_LL_100G_MAC_N5010	0x1f /* Silicom Lightning Creek */

static const struct dfl_device_id n5010_hssi_mac_ids[] = {
	{ FME_ID, FME_FEATURE_ID_LL_100G_MAC_N5010 },
	{ }
};

static struct dfl_driver n5010_hssi_driver = {
	.drv = {
		.name = "n5010_hssi",
	},
	.id_table = n5010_hssi_mac_ids,
	.probe = n5010_hssi_probe,
	.remove = n5010_hssi_remove,
};

module_dfl_driver(n5010_hssi_driver);
MODULE_DEVICE_TABLE(dfl, n5010_hssi_mac_ids);
MODULE_DESCRIPTION("Network Device Driver for Silicom Lightning Creek");
MODULE_AUTHOR("Esa Leskinen <ele@silicom.dk>");
MODULE_LICENSE("GPL v2");
