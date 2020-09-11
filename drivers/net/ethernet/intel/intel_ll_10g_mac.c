// SPDX-License-Identifier: GPL-2.0

/* Intel(R) Low Latency 10G Network Driver
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 */

#include <linux/version.h>
#include <linux/bitfield.h>
#include <linux/ethtool.h>
#include <linux/fpga/dfl-bus.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/uaccess.h>

#define CAPABILITY_OFFSET	0x08
#define MB_BASE_OFFSET		0x28

#define PHY_BASE_OFF		0x2000
#define PHY_RX_SER_LOOP_BACK	0x4e1

#define ILL_10G_TX_STATS_CLR	0x1c00
#define ILL_10G_RX_STATS_CLR	0x0c00

#define STATS_CLR_INT_US		1
#define STATS_CLR_INT_TIMEOUT_US	1000

struct intel_ll_10g_drvdata {
	struct net_device *netdev;
};

struct intel_ll_10g_ops_params {
	struct stat_info *stats;
	u32 num_stats;
	u32 tx_clr_off;
	u32 rx_clr_off;
	u32 lpbk_off;
	u32 lpbk_en_val;
};

struct intel_ll_10g_netdata {
	struct dfl_device *dfl_dev;
	struct regmap *regmap;
	struct dfl_regmap_debug *debug;
	const struct intel_ll_10g_ops_params *ops_params;
};

static int netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;

	return 0;
}

static int netdev_set_loopback(struct net_device *netdev, bool en)
{
	struct intel_ll_10g_netdata *npriv = netdev_priv(netdev);
	u32 val = 0;

	if (en)
		val = npriv->ops_params->lpbk_en_val;

	return regmap_write(npriv->regmap, npriv->ops_params->lpbk_off, val);
}

static int netdev_set_features(struct net_device *netdev,
			       netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;

	if (changed & NETIF_F_LOOPBACK)
		return netdev_set_loopback(netdev, !!(features & NETIF_F_LOOPBACK));

	return 0;
}

static int netdev_set_mac_address(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;

	memcpy(ndev->dev_addr, addr->sa_data, ETH_ALEN);

	/* TODO program hardware */

	return 0;
}

static const struct net_device_ops netdev_ops = {
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

static struct stat_info stats_10g[] = {
	/* TX Statistics */
	{STAT_INFO(0x1c02, "tx_frame_ok")},
	{STAT_INFO(0x1c04, "tx_frame_err")},
	{STAT_INFO(0x1c06, "tx_frame_crc_err")},
	{STAT_INFO(0x1c08, "tx_octets_ok")},
	{STAT_INFO(0x1c0a, "tx_pause_mac_ctrl_frames")},
	{STAT_INFO(0x1c0c, "tx_if_err")},
	{STAT_INFO(0x1c0e, "tx_unicast_frame_ok")},
	{STAT_INFO(0x1c10, "tx_unicast_frame_err")},
	{STAT_INFO(0x1c12, "tx_multicast_frame_ok")},
	{STAT_INFO(0x1c14, "tx_multicast_frame_err")},
	{STAT_INFO(0x1c16, "tx_broadcast_frame_ok")},
	{STAT_INFO(0x1c18, "tx_broadcast_frame_err")},
	{STAT_INFO(0x1c1a, "tx_ether_octets")},
	{STAT_INFO(0x1c1c, "tx_ether_pkts")},
	{STAT_INFO(0x1c1e, "tx_ether_undersize_pkts")},
	{STAT_INFO(0x1c20, "tx_ether_oversize_pkts")},
	{STAT_INFO(0x1c22, "tx_ether_pkts_64_octets")},
	{STAT_INFO(0x1c24, "tx_ether_pkts_65_127_octets")},
	{STAT_INFO(0x1c26, "tx_ether_pkts_128_255_octets")},
	{STAT_INFO(0x1c28, "tx_ether_pkts_256_511_octets")},
	{STAT_INFO(0x1c2a, "tx_ether_pkts_512_1023_octets")},
	{STAT_INFO(0x1c2c, "tx_ether_pkts_1024_1518_octets")},
	{STAT_INFO(0x1c2e, "tx_ether_pkts_1519_x_octets")},
	{STAT_INFO(0x1c30, "tx_ether_fragments")},
	{STAT_INFO(0x1c32, "tx_ether_jabbers")},
	{STAT_INFO(0x1c34, "tx_ether_crc_err")},
	{STAT_INFO(0x1c36, "tx_unicast_mac_ctrl_frames")},
	{STAT_INFO(0x1c38, "tx_multicast_mac_ctrl_frames")},
	{STAT_INFO(0x1c3a, "tx_broadcast_mac_ctrl_frames")},
	{STAT_INFO(0x1c3c, "tx_pfc_mac_ctrl_frames")},

	/* RX Statistics */
	{STAT_INFO(0x0c02, "rx_frame_ok")},
	{STAT_INFO(0x0c04, "rx_frame_err")},
	{STAT_INFO(0x0c06, "rx_frame_crc_err")},
	{STAT_INFO(0x0c08, "rx_octets_ok")},
	{STAT_INFO(0x0c0a, "rx_pause_mac_ctrl_frames")},
	{STAT_INFO(0x0c0c, "rx_if_err")},
	{STAT_INFO(0x0c0e, "rx_unicast_frame_ok")},
	{STAT_INFO(0x0c10, "rx_unicast_frame_err")},
	{STAT_INFO(0x0c12, "rx_multicast_frame_ok")},
	{STAT_INFO(0x0c14, "rx_multicast_frame_err")},
	{STAT_INFO(0x0c16, "rx_broadcast_frame_ok")},
	{STAT_INFO(0x0c18, "rx_broadcast_frame_err")},
	{STAT_INFO(0x0c1a, "rx_ether_octets")},
	{STAT_INFO(0x0c1c, "rx_ether_pkts")},
	{STAT_INFO(0x0c1e, "rx_ether_undersize_pkts")},
	{STAT_INFO(0x0c20, "rx_ether_oversize_pkts")},
	{STAT_INFO(0x0c22, "rx_ether_pkts_64_octets")},
	{STAT_INFO(0x0c24, "rx_ether_pkts_65_127_octets")},
	{STAT_INFO(0x0c26, "rx_ether_pkts_128_255_octets")},
	{STAT_INFO(0x0c28, "rx_ether_pkts_256_511_octets")},
	{STAT_INFO(0x0c2a, "rx_ether_pkts_512_1023_octets")},
	{STAT_INFO(0x0c2c, "rx_ether_pkts_1024_1518_octets")},
	{STAT_INFO(0x0c2e, "rx_ether_pkts_1519_x_octets")},
	{STAT_INFO(0x0c30, "rx_ether_fragments")},
	{STAT_INFO(0x0c32, "rx_ether_jabbers")},
	{STAT_INFO(0x0c34, "rx_ether_crc_err")},
	{STAT_INFO(0x0c36, "rx_unicast_mac_ctrl_frames")},
	{STAT_INFO(0x0c38, "rx_multicast_mac_ctrl_frames")},
	{STAT_INFO(0x0c3a, "rx_broadcast_mac_ctrl_frames")},
	{STAT_INFO(0x0c3c, "rx_pfc_mac_ctrl_frames")},
};

static void ethtool_get_strings(struct net_device *netdev, u32 stringset,
				u8 *s)
{
	struct intel_ll_10g_netdata *npriv = netdev_priv(netdev);
	unsigned int i, stats_num = 0;
	struct stat_info *stat;

	switch (stringset) {
	case ETH_SS_STATS:
		stat = npriv->ops_params->stats;
		stats_num = npriv->ops_params->num_stats;
		break;
	default:
		return;
	}

	for (i = 0; i < stats_num; i++, s += ETH_GSTRING_LEN)
		memcpy(s, stat[i].string, ETH_GSTRING_LEN);
}

static int ethtool_get_sset_count(struct net_device *netdev, int stringset)
{
	struct intel_ll_10g_netdata *npriv = netdev_priv(netdev);

	switch (stringset) {
	case ETH_SS_STATS:
		return npriv->ops_params->num_stats;

	default:
		return 0;
	}
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
	struct intel_ll_10g_netdata *npriv = netdev_priv(netdev);
	int ret;
	u32 val;

	if (*flags | ETH_RESET_MGMT) {
		regmap_write(npriv->regmap, ILL_10G_TX_STATS_CLR, 1);

		ret = regmap_read_poll_timeout(npriv->regmap,  npriv->ops_params->tx_clr_off,
					       val, (!val), STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);

		if (ret) {
			dev_err(&netdev->dev, "%s failed to clear tx stats\n", __func__);
			return ret;
		}

		regmap_write(npriv->regmap, ILL_10G_RX_STATS_CLR, 1);

		ret = regmap_read_poll_timeout(npriv->regmap,  npriv->ops_params->rx_clr_off,
					       val, (!val), STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);

		if (ret) {
			dev_err(&netdev->dev, "%s failed to clear rx stats\n", __func__);
			return ret;
		}
	}

	return 0;
}

static void ethtool_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct intel_ll_10g_netdata *npriv = netdev_priv(netdev);
	unsigned int i, stats_num = npriv->ops_params->num_stats;
	struct stat_info *stat = npriv->ops_params->stats;
	u32 flags = ETH_RESET_MGMT;

	for (i = 0; i < stats_num; i++)
		data[i] = read_mac_stat(npriv->regmap, stat[i].addr);

	ethtool_reset(netdev, &flags);
}

static const struct ethtool_ops ethtool_ops = {
	.get_strings = ethtool_get_strings,
	.get_sset_count = ethtool_get_sset_count,
	.get_ethtool_stats = ethtool_get_stats,
	.reset = ethtool_reset,
};

static const struct intel_ll_10g_ops_params intel_ll_10g_params = {
	.stats = stats_10g,
	.num_stats = ARRAY_SIZE(stats_10g),
	.tx_clr_off = ILL_10G_TX_STATS_CLR,
	.rx_clr_off = ILL_10G_RX_STATS_CLR,
	.lpbk_off = PHY_BASE_OFF + PHY_RX_SER_LOOP_BACK,
	.lpbk_en_val = 1,
};

static void intel_ll_10g_init_netdev(struct net_device *netdev)
{
	netdev->ethtool_ops = &ethtool_ops;
	netdev->netdev_ops = &netdev_ops;
	netdev->features = 0;
	netdev->hw_features |= NETIF_F_LOOPBACK;
	netdev->hard_header_len = 0;
	netdev->priv_flags |= IFF_NO_QUEUE;

	netdev->needs_free_netdev  = true;

	ether_setup(netdev);
}

static int intel_ll_10g_mac_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct intel_ll_10g_netdata *npriv;
	struct intel_ll_10g_drvdata *priv;
	struct regmap *regmap;
	void __iomem *base;
	u32 flags;
	u64 val;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);

	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);

	base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);

	if (!base)
		return -ENOMEM;

	val = readq(base + CAPABILITY_OFFSET);

	dev_info(dev, "%s capability register 0x%llx\n", __func__, val);

	regmap = dfl_indirect_regmap_init(dev, base, MB_BASE_OFFSET);

	if (!regmap)
		return -ENOMEM;

	priv->netdev = alloc_netdev(sizeof(struct intel_ll_10g_netdata),
				    "ll_10g%d", NET_NAME_UNKNOWN,
				    intel_ll_10g_init_netdev);

	if (!priv->netdev)
		return -ENOMEM;

	npriv = netdev_priv(priv->netdev);

	npriv->dfl_dev = dfl_dev;
	npriv->regmap = regmap;
	npriv->debug = dfl_regmap_debug_init(dev, regmap);
	npriv->ops_params = &intel_ll_10g_params;

	SET_NETDEV_DEV(priv->netdev, &dfl_dev->dev);

	flags = ETH_RESET_MGMT;

	ret = ethtool_reset(priv->netdev, &flags);

	if (ret)
		dev_err(&dfl_dev->dev, "failed to reset MGMT %s: %d",
			priv->netdev->name, ret);

	ret = register_netdev(priv->netdev);

	if (ret)
		dev_err(&dfl_dev->dev, "failed to register %s: %d",
			priv->netdev->name, ret);

	return ret;
}

static int intel_ll_10g_mac_remove(struct dfl_device *dfl_dev)
{
	struct intel_ll_10g_drvdata *priv = dev_get_drvdata(&dfl_dev->dev);
	struct intel_ll_10g_netdata *npriv = netdev_priv(priv->netdev);

	dfl_regmap_debug_exit(npriv->debug);

	unregister_netdev(priv->netdev);

	return 0;
}

#define FME_FEATURE_ID_LL_10G_MAC 0xf

static const struct dfl_device_id intel_ll_10g_mac_ids[] = {
	{ FME_ID, FME_FEATURE_ID_LL_10G_MAC },
	{ }
};

static struct dfl_driver intel_ll_10g_mac_driver = {
	.drv = {
		.name = "intel-ll-10g-mac",
	},
	.id_table = intel_ll_10g_mac_ids,
	.probe = intel_ll_10g_mac_probe,
	.remove = intel_ll_10g_mac_remove,
};

module_dfl_driver(intel_ll_10g_mac_driver);
MODULE_DEVICE_TABLE(dfl, intel_ll_10g_mac_ids);
MODULE_DESCRIPTION("Network Device Driver for Intel(R) Low Latency 10G MAC");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
