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

struct intel_ll_10g_drvdata {
	struct net_device *netdev;
};

struct intel_ll_10g_netdata {
	struct dfl_device *dfl_dev;
};

static int netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;

	return 0;
}

static int netdev_set_features(struct net_device *dev,
			       netdev_features_t features)
{
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
	/* {STAT_INFO(0x170, "tx_ether_fragments")}, */
	/* {STAT_INFO(0x172, "tx_ether_jabbers")}, */
	/* {STAT_INFO(0x174, "tx_ether_crc_err")}, */
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

static void ethtool_get_strings(struct net_device *netdev, u32 stringset,
				u8 *s)
{
	unsigned int i, stats_num = 0;
	struct stat_info *stat;

	switch (stringset) {
	case ETH_SS_STATS:
		stat = stats_10g;
		stats_num = ARRAY_SIZE(stats_10g);
		break;
	default:
		return;
	}

	for (i = 0; i < stats_num; i++, s += ETH_GSTRING_LEN)
		memcpy(s, stat[i].string, ETH_GSTRING_LEN);
}

static int ethtool_get_sset_count(struct net_device *netdev, int stringset)
{
	switch (stringset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(stats_10g);

	default:
		return 0;
	}
}

static void ethtool_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	unsigned int i, stats_num = ARRAY_SIZE(stats_10g);
	struct stat_info *stat = stats_10g;

	for (i = 0; i < stats_num; i++)
		data[i] = stat[i].addr;
}

static const struct ethtool_ops ethtool_ops = {
	.get_strings = ethtool_get_strings,
	.get_sset_count = ethtool_get_sset_count,
	.get_ethtool_stats = ethtool_get_stats,
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
	struct intel_ll_10g_netdata *npriv;
	struct intel_ll_10g_drvdata *priv;
	int ret;

	priv = devm_kzalloc(&dfl_dev->dev, sizeof(*priv), GFP_KERNEL);

	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(&dfl_dev->dev, priv);

	dev_info(&dfl_dev->dev, "%s priv %p\n", __func__, priv);

	priv->netdev = alloc_netdev(sizeof(struct intel_ll_10g_netdata),
				    "ll_10g%d", NET_NAME_UNKNOWN,
				    intel_ll_10g_init_netdev);

	if (!priv->netdev)
		return -ENOMEM;

	npriv = netdev_priv(priv->netdev);

	npriv->dfl_dev = dfl_dev;

	SET_NETDEV_DEV(priv->netdev, &dfl_dev->dev);

	ret = register_netdev(priv->netdev);

	if (ret)
		dev_err(&dfl_dev->dev, "failed to register %s: %d",
			priv->netdev->name, ret);

	return ret;
}

static int intel_ll_10g_mac_remove(struct dfl_device *dfl_dev)
{
	struct intel_ll_10g_drvdata *priv = dev_get_drvdata(&dfl_dev->dev);

	dev_info(&dfl_dev->dev, "%s %p\n", __func__, priv);

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
