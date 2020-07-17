// SPDX-License-Identifier: GPL-2.0
/* Driver for FPGA Management Engine (FME) Ether Group
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Xu Yilun <yilun.xu@intel.com>
 */
#include <linux/netdevice.h>

#include "dfl-eth-group.h"

/* 10G PHY Register */
#define PHY_LOOPBACK		0x2e1
#define PHY_LOOPBACK_SERIAL	BIT(0)

/* 10G MAC Register */
#define TX_FRAME_MAXLENGTH	0x2c
#define TX_PAUSE_FRAME_QUANTA	0x42
#define TX_PAUSE_FRAME_HOLDOFF	0x43
#define TX_PAUSE_FRAME_EN	0x44
#define TX_PAUSE_FRAME_EN_CFG	BIT(0)
#define RX_FRAME_MAXLENGTH	0xae

/* Additional Feature Register */
#define ADD_PHY_CTRL		0x0
#define PHY_RESET		BIT(0)

static int edev10g_reset(struct eth_dev *edev, bool en)
{
	struct eth_com *phy = edev->phy;
	struct device *dev = edev->dev;
	u32 val;
	int ret;

	/* 10G eth group supports PHY reset. It uses external reset. */
	ret = eth_com_add_feat_read_reg(phy, ADD_PHY_CTRL, &val);
	if (ret) {
		dev_err(dev, "fail to read ADD_PHY_CTRL reg: %d\n", ret);
		return ret;
	}

	/* return if PHY is already in expected state */
	if ((val & PHY_RESET && en) || (!(val & PHY_RESET) && !en))
		return 0;

	if (en)
		val |= PHY_RESET;
	else
		val &= ~PHY_RESET;

	ret = eth_com_add_feat_write_reg(phy, ADD_PHY_CTRL, val);
	if (ret)
		dev_err(dev, "fail to write ADD_PHY_CTRL reg: %d\n", ret);

	return ret;
}

static ssize_t tx_pause_frame_quanta_show(struct device *d,
					  struct device_attribute *attr,
					  char *buf)
{
	struct eth_dev *edev = net_device_to_eth_dev(to_net_dev(d));
	u32 data;
	int ret;

	ret = eth_com_read_reg(edev->mac, TX_PAUSE_FRAME_QUANTA, &data);

	return ret ? : sprintf(buf, "0x%x\n", data);
}

static ssize_t tx_pause_frame_quanta_store(struct device *d,
					   struct device_attribute *attr,
					   const char *buf, size_t len)
{
	struct net_device *netdev = to_net_dev(d);
	struct eth_dev *edev;
	u32 data;
	int ret;

	if (kstrtou32(buf, 0, &data))
		return -EINVAL;

	edev = net_device_to_eth_dev(netdev);

	rtnl_lock();

	if (netif_running(netdev)) {
		netdev_err(netdev, "must be stopped to change pause param\n");
		ret = -EBUSY;
		goto out;
	}

	ret = eth_com_write_reg(edev->mac, TX_PAUSE_FRAME_QUANTA, data);

out:
	rtnl_unlock();

	return ret ? : len;
}
static DEVICE_ATTR_RW(tx_pause_frame_quanta);

static ssize_t tx_pause_frame_holdoff_show(struct device *d,
					   struct device_attribute *attr,
					   char *buf)
{
	struct eth_dev *edev = net_device_to_eth_dev(to_net_dev(d));
	u32 data;
	int ret;

	ret = eth_com_read_reg(edev->mac, TX_PAUSE_FRAME_HOLDOFF, &data);

	return ret ? : sprintf(buf, "0x%x\n", data);
}

static ssize_t tx_pause_frame_holdoff_store(struct device *d,
					    struct device_attribute *attr,
					    const char *buf, size_t len)
{
	struct net_device *netdev = to_net_dev(d);
	struct eth_dev *edev;
	u32 data;
	int ret;

	if (kstrtou32(buf, 0, &data))
		return -EINVAL;

	edev = net_device_to_eth_dev(netdev);

	rtnl_lock();

	if (netif_running(netdev)) {
		netdev_err(netdev, "must be stopped to change pause param\n");
		ret = -EBUSY;
		goto out;
	}

	ret = eth_com_write_reg(edev->mac, TX_PAUSE_FRAME_HOLDOFF, data);

out:
	rtnl_unlock();

	return ret ? : len;
}
static DEVICE_ATTR_RW(tx_pause_frame_holdoff);

static struct attribute *edev10g_dev_attrs[] = {
	&dev_attr_tx_pause_frame_quanta.attr,
	&dev_attr_tx_pause_frame_holdoff.attr,
	NULL
};

/* device attributes */
static const struct attribute_group edev10g_attr_group = {
	.attrs = edev10g_dev_attrs,
};

/* ethtool ops */
static struct stat_info stats_10g[] = {
	/* TX Statistics */
	{STAT_INFO(0x142, "tx_frame_ok")},
	{STAT_INFO(0x144, "tx_frame_err")},
	{STAT_INFO(0x146, "tx_frame_crc_err")},
	{STAT_INFO(0x148, "tx_octets_ok")},
	{STAT_INFO(0x14a, "tx_pause_mac_ctrl_frames")},
	{STAT_INFO(0x14c, "tx_if_err")},
	{STAT_INFO(0x14e, "tx_unicast_frame_ok")},
	{STAT_INFO(0x150, "tx_unicast_frame_err")},
	{STAT_INFO(0x152, "tx_multicast_frame_ok")},
	{STAT_INFO(0x154, "tx_multicast_frame_err")},
	{STAT_INFO(0x156, "tx_broadcast_frame_ok")},
	{STAT_INFO(0x158, "tx_broadcast_frame_err")},
	{STAT_INFO(0x15a, "tx_ether_octets")},
	{STAT_INFO(0x15c, "tx_ether_pkts")},
	{STAT_INFO(0x15e, "tx_ether_undersize_pkts")},
	{STAT_INFO(0x160, "tx_ether_oversize_pkts")},
	{STAT_INFO(0x162, "tx_ether_pkts_64_octets")},
	{STAT_INFO(0x164, "tx_ether_pkts_65_127_octets")},
	{STAT_INFO(0x166, "tx_ether_pkts_128_255_octets")},
	{STAT_INFO(0x168, "tx_ether_pkts_256_511_octets")},
	{STAT_INFO(0x16a, "tx_ether_pkts_512_1023_octets")},
	{STAT_INFO(0x16c, "tx_ether_pkts_1024_1518_octets")},
	{STAT_INFO(0x16e, "tx_ether_pkts_1519_x_octets")},
	{STAT_INFO(0x176, "tx_unicast_mac_ctrl_frames")},
	{STAT_INFO(0x178, "tx_multicast_mac_ctrl_frames")},
	{STAT_INFO(0x17a, "tx_broadcast_mac_ctrl_frames")},
	{STAT_INFO(0x17c, "tx_pfc_mac_ctrl_frames")},

	/* RX Statistics */
	{STAT_INFO(0x1c2, "rx_frame_ok")},
	{STAT_INFO(0x1c4, "rx_frame_err")},
	{STAT_INFO(0x1c6, "rx_frame_crc_err")},
	{STAT_INFO(0x1c8, "rx_octets_ok")},
	{STAT_INFO(0x1ca, "rx_pause_mac_ctrl_frames")},
	{STAT_INFO(0x1cc, "rx_if_err")},
	{STAT_INFO(0x1ce, "rx_unicast_frame_ok")},
	{STAT_INFO(0x1d0, "rx_unicast_frame_err")},
	{STAT_INFO(0x1d2, "rx_multicast_frame_ok")},
	{STAT_INFO(0x1d4, "rx_multicast_frame_err")},
	{STAT_INFO(0x1d6, "rx_broadcast_frame_ok")},
	{STAT_INFO(0x1d8, "rx_broadcast_frame_err")},
	{STAT_INFO(0x1da, "rx_ether_octets")},
	{STAT_INFO(0x1dc, "rx_ether_pkts")},
	{STAT_INFO(0x1de, "rx_ether_undersize_pkts")},
	{STAT_INFO(0x1e0, "rx_ether_oversize_pkts")},
	{STAT_INFO(0x1e2, "rx_ether_pkts_64_octets")},
	{STAT_INFO(0x1e4, "rx_ether_pkts_65_127_octets")},
	{STAT_INFO(0x1e6, "rx_ether_pkts_128_255_octets")},
	{STAT_INFO(0x1e8, "rx_ether_pkts_256_511_octets")},
	{STAT_INFO(0x1ea, "rx_ether_pkts_512_1023_octets")},
	{STAT_INFO(0x1ec, "rx_ether_pkts_1024_1518_octets")},
	{STAT_INFO(0x1ee, "rx_ether_pkts_1519_x_octets")},
	{STAT_INFO(0x1f0, "rx_ether_fragments")},
	{STAT_INFO(0x1f2, "rx_ether_jabbers")},
	{STAT_INFO(0x1f4, "rx_ether_crc_err")},
	{STAT_INFO(0x1f6, "rx_unicast_mac_ctrl_frames")},
	{STAT_INFO(0x1f8, "rx_multicast_mac_ctrl_frames")},
	{STAT_INFO(0x1fa, "rx_broadcast_mac_ctrl_frames")},
	{STAT_INFO(0x1fc, "rx_pfc_mac_ctrl_frames")},
};

static void edev10g_get_strings(struct net_device *netdev, u32 stringset, u8 *s)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	unsigned int i;

	if (stringset != ETH_SS_STATS || edev->lw_mac)
		return;

	for (i = 0; i < ARRAY_SIZE(stats_10g); i++, s += ETH_GSTRING_LEN)
		memcpy(s, stats_10g[i].string, ETH_GSTRING_LEN);
}

static int edev10g_get_sset_count(struct net_device *netdev, int stringset)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);

	if (stringset != ETH_SS_STATS || edev->lw_mac)
		return -EOPNOTSUPP;

	return (int)ARRAY_SIZE(stats_10g);
}

static void edev10g_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	unsigned int i;

	if (edev->lw_mac || !netif_running(netdev))
		return;

	for (i = 0; i < ARRAY_SIZE(stats_10g); i++)
		data[i] = read_mac_stats(edev->mac, stats_10g[i].addr);
}

static int edev10g_get_link_ksettings(struct net_device *netdev,
				      struct ethtool_link_ksettings *cmd)
{
	if (!netdev->phydev)
		return -ENODEV;

	phy_ethtool_ksettings_get(netdev->phydev, cmd);

	return 0;
}

static void edev10g_get_pauseparam(struct net_device *netdev,
				   struct ethtool_pauseparam *pause)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	u32 data;
	int ret;

	pause->autoneg = 0;
	pause->rx_pause = 0;

	ret = eth_com_read_reg(edev->mac, TX_PAUSE_FRAME_EN, &data);
	if (ret) {
		pause->tx_pause = 0;
		return;
	}

	pause->tx_pause = (data & TX_PAUSE_FRAME_EN_CFG) ? 0x1 : 0;
}

static int edev10g_set_pauseparam(struct net_device *netdev,
				  struct ethtool_pauseparam *pause)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *mac = edev->mac;
	bool enable = pause->tx_pause;
	u32 data;
	int ret;

	if (pause->autoneg || pause->rx_pause)
		return -EOPNOTSUPP;

	if (netif_running(netdev)) {
		netdev_err(netdev, "must be stopped to change pause param\n");
		return -EBUSY;
	}

	ret = eth_com_read_reg(mac, TX_PAUSE_FRAME_EN, &data);
	if (ret)
		return ret;

	if (enable)
		data |= TX_PAUSE_FRAME_EN_CFG;
	else
		data &= ~TX_PAUSE_FRAME_EN_CFG;

	return eth_com_write_reg(mac, TX_PAUSE_FRAME_EN, data);
}

static const struct ethtool_ops edev10g_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_strings = edev10g_get_strings,
	.get_sset_count = edev10g_get_sset_count,
	.get_ethtool_stats = edev10g_get_stats,
	.get_link_ksettings = edev10g_get_link_ksettings,
	.get_pauseparam = edev10g_get_pauseparam,
	.set_pauseparam = edev10g_set_pauseparam,
};

/* netdev ops */
static int edev10g_netdev_open(struct net_device *netdev)
{
	struct n3000_net_priv *priv = netdev_priv(netdev);
	struct eth_dev *edev = priv->edev;
	int ret;

	ret = edev10g_reset(edev, false);
	if (ret)
		return ret;

	if (netdev->phydev)
		phy_start(netdev->phydev);

	return 0;
}

static int edev10g_netdev_stop(struct net_device *netdev)
{
	struct n3000_net_priv *priv = netdev_priv(netdev);
	struct eth_dev *edev = priv->edev;
	int ret;

	ret = edev10g_reset(edev, true);
	if (ret)
		return ret;

	if (netdev->phydev)
		phy_stop(netdev->phydev);

	return 0;
}

static int edev10g_mtu_init(struct net_device *netdev)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *mac = edev->mac;
	u32 tx = 0, rx = 0, mtu;
	int ret;

	ret = eth_com_read_reg(mac, TX_FRAME_MAXLENGTH, &tx);
	if (ret)
		return ret;

	ret = eth_com_read_reg(mac, RX_FRAME_MAXLENGTH, &rx);
	if (ret)
		return ret;

	mtu = min(min(tx, rx), netdev->max_mtu);

	ret = eth_com_write_reg(mac, TX_FRAME_MAXLENGTH, rx);
	if (ret)
		return ret;

	ret = eth_com_write_reg(mac, RX_FRAME_MAXLENGTH, tx);
	if (ret)
		return ret;

	netdev->mtu = mtu;

	return 0;
}

static int edev10g_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *mac = edev->mac;
	int ret;

	if (netif_running(netdev)) {
		netdev_err(netdev, "must be stopped to change mtu\n");
		return -EBUSY;
	}

	ret = eth_com_write_reg(mac, TX_FRAME_MAXLENGTH, new_mtu);
	if (ret)
		return ret;

	ret = eth_com_write_reg(mac, RX_FRAME_MAXLENGTH, new_mtu);
	if (ret)
		return ret;

	netdev->mtu = new_mtu;

	return 0;
}

static int edev10g_set_loopback(struct net_device *netdev, bool en)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *phy = edev->phy;
	u32 data;
	int ret;

	ret = eth_com_read_reg(phy, PHY_LOOPBACK, &data);
	if (ret)
		return ret;

	if (en)
		data |= PHY_LOOPBACK_SERIAL;
	else
		data &= ~PHY_LOOPBACK_SERIAL;

	return eth_com_write_reg(phy, PHY_LOOPBACK, data);
}

static int edev10g_set_features(struct net_device *netdev,
				netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;

	if (changed & NETIF_F_LOOPBACK)
		return edev10g_set_loopback(netdev,
					    !!(features & NETIF_F_LOOPBACK));

	return 0;
}

static const struct net_device_ops edev10g_netdev_ops = {
	.ndo_open = edev10g_netdev_open,
	.ndo_stop = edev10g_netdev_stop,
	.ndo_change_mtu = edev10g_change_mtu,
	.ndo_set_features = edev10g_set_features,
	.ndo_start_xmit = n3000_dummy_netdev_xmit,
};

static void edev10g_adjust_link(struct net_device *netdev)
{}

static int edev10g_netdev_init(struct net_device *netdev)
{
	int ret;

	ret = edev10g_mtu_init(netdev);
	if (ret)
		return ret;

	return edev10g_set_loopback(netdev,
				   !!(netdev->features & NETIF_F_LOOPBACK));
}

static int dfl_eth_dev_10g_init(struct eth_dev *edev)
{
	__ETHTOOL_DECLARE_LINK_MODE_MASK(mask) = { 0, };
	struct device *dev = edev->dev;
	struct phy_device *phydev;
	struct net_device *netdev;
	int ret;

	netdev = n3000_netdev_create(edev);
	if (!netdev)
		return -ENOMEM;

	netdev->hw_features |= NETIF_F_LOOPBACK;
	netdev->netdev_ops = &edev10g_netdev_ops;
	netdev->ethtool_ops = &edev10g_ethtool_ops;

	phydev = phy_connect(netdev, edev->phy_id, edev10g_adjust_link,
			     PHY_INTERFACE_MODE_NA);
	if (IS_ERR(phydev)) {
		dev_err(dev, "PHY connection failed\n");
		ret = PTR_ERR(phydev);
		goto err_free_netdev;
	}

	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, mask);
	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseSR_Full_BIT, mask);
	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseLR_Full_BIT, mask);
	linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, mask);
	linkmode_and(phydev->supported, phydev->supported, mask);
	linkmode_copy(phydev->advertising, phydev->supported);

	phy_attached_info(phydev);

	ret = edev10g_netdev_init(netdev);
	if (ret) {
		dev_err(dev, "fail to init netdev %s\n", netdev->name);
		goto err_phy_disconnect;
	}

	netdev->sysfs_groups[0] = &edev10g_attr_group;

	netif_carrier_off(netdev);
	ret = register_netdev(netdev);
	if (ret) {
		dev_err(dev, "fail to register netdev %s\n", netdev->name);
		goto err_phy_disconnect;
	}

	edev->netdev = netdev;

	return 0;

err_phy_disconnect:
	if (netdev->phydev)
		phy_disconnect(phydev);
err_free_netdev:
	free_netdev(netdev);

	return ret;
}

static void dfl_eth_dev_10g_remove(struct eth_dev *edev)
{
	struct net_device *netdev = edev->netdev;

	if (netdev->phydev)
		phy_disconnect(netdev->phydev);

	unregister_netdev(netdev);
}

struct eth_dev_ops dfl_eth_dev_10g_ops = {
	.lineside_init = dfl_eth_dev_10g_init,
	.lineside_remove = dfl_eth_dev_10g_remove,
	.reset = edev10g_reset,
};
