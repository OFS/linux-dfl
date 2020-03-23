// SPDX-License-Identifier: GPL-2.0
/* Driver for 25G Ether Group private feature on Intel PAC (Programmable
 * Acceleration Card) N3000
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Xu Yilun <yilun.xu@intel.com>
 */
#include <linux/netdevice.h>

#include "dfl-eth-group.h"

/* 25G PHY/MAC Register */
#define PHY_CONFIG	0x310
#define PHY_MAC_RESET_MASK	GENMASK(2, 0)
#define PHY_PMA_SLOOP		0x313
#define MAX_TX_SIZE_CONFIG	0x407
#define MAX_RX_SIZE_CONFIG	0x506
#define TX_FLOW_CTRL_EN		0x605
#define TX_FLOW_CTRL_EN_PAUSE	BIT(0)
#define TX_FLOW_CTRL_QUANTA	0x620
#define TX_FLOW_CTRL_HOLDOFF	0x628
#define TX_FLOW_CTRL_SEL	0x640
#define TX_FLOW_CTRL_SEL_PAUSE	0x0
#define TX_FLOW_CTRL_SEL_PFC	0x1

static int edev25g40g_reset(struct eth_dev *edev, bool en)
{
	struct eth_com *mac = edev->mac;
	struct device *dev = edev->dev;
	u32 val;
	int ret;

	ret = eth_com_read_reg(mac, PHY_CONFIG, &val);
	if (ret) {
		dev_err(dev, "fail to read PHY_CONFIG: %d\n", ret);
		return ret;
	}

	/* skip if config is in expected state already */
	if ((((val & PHY_MAC_RESET_MASK) == PHY_MAC_RESET_MASK) && en) ||
	    (((val & PHY_MAC_RESET_MASK) == 0) && !en))
		return 0;

	if (en)
		val |= PHY_MAC_RESET_MASK;
	else
		val &= ~PHY_MAC_RESET_MASK;

	ret = eth_com_write_reg(mac, PHY_CONFIG, val);
	if (ret)
		dev_err(dev, "fail to write PHY_CONFIG: %d\n", ret);

	return ret;
}

static ssize_t tx_pause_frame_quanta_show(struct device *d,
					  struct device_attribute *attr,
					  char *buf)
{
	struct eth_dev *edev = net_device_to_eth_dev(to_net_dev(d));
	u32 data;
	int ret;

	ret = eth_com_read_reg(edev->mac, TX_FLOW_CTRL_QUANTA, &data);

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

	ret = eth_com_write_reg(edev->mac, TX_FLOW_CTRL_QUANTA, data);

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

	ret = eth_com_read_reg(edev->mac, TX_FLOW_CTRL_HOLDOFF, &data);

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

	ret = eth_com_write_reg(edev->mac, TX_FLOW_CTRL_HOLDOFF, data);

out:
	rtnl_unlock();

	return ret ? : len;
}
static DEVICE_ATTR_RW(tx_pause_frame_holdoff);

static struct attribute *edev25g_dev_attrs[] = {
	&dev_attr_tx_pause_frame_quanta.attr,
	&dev_attr_tx_pause_frame_holdoff.attr,
	NULL
};

/* device attributes */
static const struct attribute_group edev25g_attr_group = {
	.attrs = edev25g_dev_attrs,
};

/* ethtool ops */
static struct stat_info stats_25g[] = {
	/* TX Statistics */
	{STAT_INFO(0x800, "tx_fragments")},
	{STAT_INFO(0x802, "tx_jabbers")},
	{STAT_INFO(0x804, "tx_fcs")},
	{STAT_INFO(0x806, "tx_crc_err")},
	{STAT_INFO(0x808, "tx_mcast_data_err")},
	{STAT_INFO(0x80a, "tx_bcast_data_err")},
	{STAT_INFO(0x80c, "tx_ucast_data_err")},
	{STAT_INFO(0x80e, "tx_mcast_ctrl_err")},
	{STAT_INFO(0x810, "tx_bcast_ctrl_err")},
	{STAT_INFO(0x812, "tx_ucast_ctrl_err")},
	{STAT_INFO(0x814, "tx_pause_err")},
	{STAT_INFO(0x816, "tx_64_byte")},
	{STAT_INFO(0x818, "tx_65_127_byte")},
	{STAT_INFO(0x81a, "tx_128_255_byte")},
	{STAT_INFO(0x81c, "tx_256_511_byte")},
	{STAT_INFO(0x81e, "tx_512_1023_byte")},
	{STAT_INFO(0x820, "tx_1024_1518_byte")},
	{STAT_INFO(0x822, "tx_1519_max_byte")},
	{STAT_INFO(0x824, "tx_oversize")},
	{STAT_INFO(0x826, "tx_mcast_data_ok")},
	{STAT_INFO(0x828, "tx_bcast_data_ok")},
	{STAT_INFO(0x82a, "tx_ucast_data_ok")},
	{STAT_INFO(0x82c, "tx_mcast_ctrl_ok")},
	{STAT_INFO(0x82e, "tx_bcast_ctrl_ok")},
	{STAT_INFO(0x830, "tx_ucast_ctrl_ok")},
	{STAT_INFO(0x832, "tx_pause")},
	{STAT_INFO(0x834, "tx_runt")},
	{STAT_INFO(0x860, "tx_payload_octets_ok")},
	{STAT_INFO(0x862, "tx_frame_octets_ok")},

	/* RX Statistics */
	{STAT_INFO(0x900, "rx_fragments")},
	{STAT_INFO(0x902, "rx_jabbers")},
	{STAT_INFO(0x904, "rx_fcs")},
	{STAT_INFO(0x906, "rx_crc_err")},
	{STAT_INFO(0x908, "rx_mcast_data_err")},
	{STAT_INFO(0x90a, "rx_bcast_data_err")},
	{STAT_INFO(0x90c, "rx_ucast_data_err")},
	{STAT_INFO(0x90e, "rx_mcast_ctrl_err")},
	{STAT_INFO(0x910, "rx_bcast_ctrl_err")},
	{STAT_INFO(0x912, "rx_ucast_ctrl_err")},
	{STAT_INFO(0x914, "rx_pause_err")},
	{STAT_INFO(0x916, "rx_64_byte")},
	{STAT_INFO(0x918, "rx_65_127_byte")},
	{STAT_INFO(0x91a, "rx_128_255_byte")},
	{STAT_INFO(0x91c, "rx_256_511_byte")},
	{STAT_INFO(0x91e, "rx_512_1023_byte")},
	{STAT_INFO(0x920, "rx_1024_1518_byte")},
	{STAT_INFO(0x922, "rx_1519_max_byte")},
	{STAT_INFO(0x924, "rx_oversize")},
	{STAT_INFO(0x926, "rx_mcast_data_ok")},
	{STAT_INFO(0x928, "rx_bcast_data_ok")},
	{STAT_INFO(0x92a, "rx_ucast_data_ok")},
	{STAT_INFO(0x92c, "rx_mcast_ctrl_ok")},
	{STAT_INFO(0x92e, "rx_bcast_ctrl_ok")},
	{STAT_INFO(0x930, "rx_ucast_ctrl_ok")},
	{STAT_INFO(0x932, "rx_pause")},
	{STAT_INFO(0x934, "rx_runt")},
	{STAT_INFO(0x960, "rx_payload_octets_ok")},
	{STAT_INFO(0x962, "rx_frame_octets_ok")},
};

static void edev25g_get_strings(struct net_device *netdev, u32 stringset, u8 *s)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	unsigned int i;

	if (stringset != ETH_SS_STATS || edev->lw_mac)
		return;

	for (i = 0; i < ARRAY_SIZE(stats_25g); i++, s += ETH_GSTRING_LEN)
		memcpy(s, stats_25g[i].string, ETH_GSTRING_LEN);
}

static int edev25g_get_sset_count(struct net_device *netdev, int stringset)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);

	if (stringset != ETH_SS_STATS || edev->lw_mac)
		return -EOPNOTSUPP;

	return (int)ARRAY_SIZE(stats_25g);
}

static void edev25g_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	unsigned int i;

	if (edev->lw_mac || !netif_running(netdev))
		return;

	for (i = 0; i < ARRAY_SIZE(stats_25g); i++)
		data[i] = read_mac_stats(edev->mac, stats_25g[i].addr);
}

static int edev25g_get_link_ksettings(struct net_device *netdev,
				      struct ethtool_link_ksettings *cmd)
{
	if (!netdev->phydev)
		return -ENODEV;

	phy_ethtool_ksettings_get(netdev->phydev, cmd);

	return 0;
}

static int edev25g_pause_init(struct net_device *netdev)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);

	return eth_com_write_reg(edev->mac, TX_FLOW_CTRL_SEL,
				 TX_FLOW_CTRL_SEL_PAUSE);
}

static void edev25g_get_pauseparam(struct net_device *netdev,
				   struct ethtool_pauseparam *pause)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	u32 data;
	int ret;

	pause->autoneg = 0;
	pause->rx_pause = 0;

	ret = eth_com_read_reg(edev->mac, TX_FLOW_CTRL_EN, &data);
	if (ret) {
		pause->tx_pause = 0;
		return;
	}

	pause->tx_pause = (data & TX_FLOW_CTRL_EN_PAUSE) ? 0x1 : 0;
}

static int edev25g_set_pauseparam(struct net_device *netdev,
				  struct ethtool_pauseparam *pause)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	bool enable = pause->tx_pause;

	if (pause->autoneg || pause->rx_pause)
		return -EOPNOTSUPP;

	return eth_com_write_reg(edev->mac, TX_FLOW_CTRL_EN,
				 enable ? TX_FLOW_CTRL_EN_PAUSE : 0);
}

static const struct ethtool_ops edev25g_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_strings = edev25g_get_strings,
	.get_sset_count = edev25g_get_sset_count,
	.get_ethtool_stats = edev25g_get_stats,
	.get_link_ksettings = edev25g_get_link_ksettings,
	.get_pauseparam = edev25g_get_pauseparam,
	.set_pauseparam = edev25g_set_pauseparam,
};

/* netdev ops */
static int edev25g_netdev_open(struct net_device *netdev)
{
	struct n3000_net_priv *priv = netdev_priv(netdev);
	struct eth_dev *edev = priv->edev;
	int ret;

	ret = edev25g40g_reset(edev, false);
	if (ret)
		return ret;

	if (netdev->phydev)
		phy_start(netdev->phydev);

	return 0;
}

static int edev25g_netdev_stop(struct net_device *netdev)
{
	struct n3000_net_priv *priv = netdev_priv(netdev);
	struct eth_dev *edev = priv->edev;
	int ret;

	ret = edev25g40g_reset(edev, true);
	if (ret)
		return ret;

	if (netdev->phydev)
		phy_stop(netdev->phydev);

	return 0;
}

static int edev25g_mtu_init(struct net_device *netdev)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *mac = edev->mac;
	u32 tx = 0, rx = 0, mtu;
	int ret;

	ret = eth_com_read_reg(mac, MAX_TX_SIZE_CONFIG, &tx);
	if (ret)
		return ret;

	ret = eth_com_read_reg(mac, MAX_RX_SIZE_CONFIG, &rx);
	if (ret)
		return ret;

	mtu = min(min(tx, rx), netdev->max_mtu);

	ret = eth_com_write_reg(mac, MAX_TX_SIZE_CONFIG, rx);
	if (ret)
		return ret;

	ret = eth_com_write_reg(mac, MAX_RX_SIZE_CONFIG, tx);
	if (ret)
		return ret;

	netdev->mtu = mtu;

	return 0;
}

static int edev25g_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);
	struct eth_com *mac = edev->mac;
	int ret;

	ret = eth_com_write_reg(mac, MAX_TX_SIZE_CONFIG, new_mtu);
	if (ret)
		return ret;

	ret = eth_com_write_reg(mac, MAX_RX_SIZE_CONFIG, new_mtu);
	if (ret)
		return ret;

	netdev->mtu = new_mtu;

	return 0;
}

static int edev25g_set_loopback(struct net_device *netdev, bool en)
{
	struct eth_dev *edev = net_device_to_eth_dev(netdev);

	return eth_com_write_reg(edev->mac, PHY_PMA_SLOOP, en);
}

static int edev25g_set_features(struct net_device *netdev,
				netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;

	if (changed & NETIF_F_LOOPBACK)
		return edev25g_set_loopback(netdev,
					    !!(features & NETIF_F_LOOPBACK));

	return 0;
}

static const struct net_device_ops edev25g_netdev_ops = {
	.ndo_open = edev25g_netdev_open,
	.ndo_stop = edev25g_netdev_stop,
	.ndo_change_mtu = edev25g_change_mtu,
	.ndo_set_features = edev25g_set_features,
	.ndo_start_xmit = n3000_dummy_netdev_xmit,
};

static void edev25g_adjust_link(struct net_device *netdev)
{}

static int edev25g_netdev_init(struct net_device *netdev)
{
	int ret;

	ret = edev25g_pause_init(netdev);
	if (ret)
		return ret;

	ret = edev25g_mtu_init(netdev);
	if (ret)
		return ret;

	return edev25g_set_loopback(netdev,
				    !!(netdev->features & NETIF_F_LOOPBACK));
}

static int dfl_eth_dev_25g_init(struct eth_dev *edev)
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
	netdev->netdev_ops = &edev25g_netdev_ops;
	netdev->ethtool_ops = &edev25g_ethtool_ops;

	phydev = phy_connect(netdev, edev->phy_id, edev25g_adjust_link,
			     PHY_INTERFACE_MODE_NA);
	if (IS_ERR(phydev)) {
		dev_err(dev, "PHY connection failed\n");
		ret = PTR_ERR(phydev);
		goto err_free_netdev;
	}

	linkmode_set_bit(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT, mask);
	linkmode_set_bit(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT, mask);
	linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, mask);
	linkmode_and(phydev->supported, phydev->supported, mask);
	linkmode_copy(phydev->advertising, phydev->supported);

	phy_attached_info(phydev);

	ret = edev25g_netdev_init(netdev);
	if (ret) {
		dev_err(dev, "fail to init netdev %s\n", netdev->name);
		goto err_phy_disconnect;
	}

	netdev->sysfs_groups[0] = &edev25g_attr_group;

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

static void dfl_eth_dev_25g_remove(struct eth_dev *edev)
{
	struct net_device *netdev = edev->netdev;

	if (netdev->phydev)
		phy_disconnect(netdev->phydev);

	unregister_netdev(netdev);
}

struct eth_dev_ops dfl_eth_dev_25g_ops = {
	.lineside_init = dfl_eth_dev_25g_init,
	.lineside_remove = dfl_eth_dev_25g_remove,
	.reset = edev25g40g_reset,
};

struct eth_dev_ops dfl_eth_dev_40g_ops = {
	.reset = edev25g40g_reset,
};
