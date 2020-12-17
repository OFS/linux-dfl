// SPDX-License-Identifier: GPL-2.0

/* Intel(R) Low Latency 10G Network Driver
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 */

#include <linux/bitfield.h>
#include <linux/dfl.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/regmap.h>
#include <linux/uaccess.h>

#define CAPABILITY_OFF		0x08
#define CAP_AVAILABLE_RATES	GENMASK_ULL(7, 0)
#define CAP_CONTAINS_PCS	GENMASK_ULL(15, 8)
#define CAP_CONTAINS_FEC	GENMASK_ULL(23, 16)
#define CAP_RATE_1G		BIT_ULL(0)
#define CAP_RATE_10G		BIT_ULL(1)
#define CAP_RATE_25G		BIT_ULL(2)
#define CAP_RATE_40G		BIT_ULL(3)
#define CAP_RATE_50G		BIT_ULL(4)
#define CAP_RATE_100G		BIT_ULL(5)
#define CAP_RATE_200G		BIT_ULL(6)
#define CAP_RATE_400G		BIT_ULL(7)

#define MB_BASE_OFF		0x28

#define PHY_BASE_OFF		0x2000
#define PHY_RX_LOCKED_OFF	0x480
#define PHY_RX_LOCKED_DATA	(BIT(0) | BIT(1))

#define PHY_RX_SER_LOOP_BACK	0x4e1
#define PHY_MAX_OFF		0x541

#define ILL_10G_BASE_OFF	0
#define ILL_10G_MAX_OFF		0x1d00
#define ILL_10G_TX_STATS_CLR	0x1c00
#define ILL_10G_RX_STATS_CLR	0x0c00

#define ILL_100G_BASE_OFF	0x400
#define ILL_100G_MAX_OFF	0x9ff
#define ILL_100G_TX_STATS_CLR	0x845
#define ILL_100G_RX_STATS_CLR	0x945

#define ILL_100G_PHY_BASE_OFF	0x300
#define ILL_100G_RX_PCS_ALN_OFF	0x326
#define ILL_100G_RX_RCS_ALIGNED BIT(0)

#define ILL_100G_LPBK_OFF	0x313
#define ILL_100G_LPBK_EN_VAL	0xffff

#define ILL_100G_PHY_MAX_OFF	0x3ff

#define ILL_100G_TX_FEC_OFF	0xc00
#define ILL_100G_TX_FEC_MAX_OFF	0xc07

#define ILL_100G_RX_FEC_OFF	0xd00
#define ILL_100G_RX_FEC_ST	0xd06
#define ILL_100G_RX_FEC_ST_ALN	BIT(4)
#define ILL_100G_RX_FEC_MAX_OFF	0xd08

#define STATS_CLR_INT_US		1
#define STATS_CLR_INT_TIMEOUT_US	1000

struct s10hssi_drvdata {
	struct net_device *netdev;
	struct timer_list poll_timer;
	struct work_struct poll_workq;
};

struct s10hssi_ops_params {
	struct stat_info *stats;
	u32 num_stats;
	u32 tx_clr_off;
	u32 rx_clr_off;
	u32 lpbk_off;
	u32 lpbk_en_val;
	u32 link_off;
	u32 link_mask;
};

struct s10hssi_netdata {
	struct dfl_device *dfl_dev;
	struct regmap *regmap;
	struct s10hssi_ops_params *ops_params;
	u32 link_status;
};

static void poll_work(struct work_struct *arg)
{
	struct s10hssi_netdata *npriv;
	struct s10hssi_drvdata *priv;
	u32 link_status = 0;

	priv = container_of(arg, struct s10hssi_drvdata, poll_workq);
	npriv = netdev_priv(priv->netdev);

	regmap_read(npriv->regmap, npriv->ops_params->link_off, &link_status);
	link_status &= npriv->ops_params->link_mask;
	if (link_status != npriv->link_status) {
		npriv->link_status = link_status;
		dev_dbg(&priv->netdev->dev, "link state: %u\n", link_status);

		if (link_status == npriv->ops_params->link_mask)
			netif_carrier_on(priv->netdev);
		else
			netif_carrier_off(priv->netdev);
	}
}

static void poll_timerf(struct timer_list *timer_arg)
{
	struct s10hssi_drvdata *priv = from_timer(priv, timer_arg, poll_timer);

	schedule_work(&priv->poll_workq);
	mod_timer(&priv->poll_timer, jiffies + msecs_to_jiffies(1000));
}

static int netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;

	return 0;
}

static int netdev_set_loopback(struct net_device *netdev, bool en)
{
	struct s10hssi_netdata *npriv = netdev_priv(netdev);
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
	struct s10hssi_netdata *npriv = netdev_priv(netdev);
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
	struct s10hssi_netdata *npriv = netdev_priv(netdev);

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
	struct s10hssi_netdata *npriv = netdev_priv(netdev);
	int ret;
	u32 val;

	if (*flags | ETH_RESET_MGMT) {
		regmap_write(npriv->regmap, npriv->ops_params->tx_clr_off, 1);

		ret = regmap_read_poll_timeout(npriv->regmap,  npriv->ops_params->tx_clr_off,
					       val, (!val), STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);

		if (ret) {
			dev_err(&netdev->dev, "%s failed to clear tx stats\n", __func__);
			return ret;
		}

		regmap_write(npriv->regmap, npriv->ops_params->rx_clr_off, 1);

		ret = regmap_read_poll_timeout(npriv->regmap,  npriv->ops_params->rx_clr_off,
					       val, (!val), STATS_CLR_INT_US,
					       STATS_CLR_INT_TIMEOUT_US);

		if (ret) {
			dev_err(&netdev->dev, "%s failed to clear rx stats\n", __func__);
			return ret;
		}
		dev_info(&netdev->dev, "%s reset statistics registers\n", __func__);
	}

	return 0;
}

static void ethtool_get_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct s10hssi_netdata *npriv = netdev_priv(netdev);
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

static const struct s10hssi_ops_params s10hssi_params = {
	.stats = stats_10g,
	.num_stats = ARRAY_SIZE(stats_10g),
	.tx_clr_off = ILL_10G_TX_STATS_CLR,
	.rx_clr_off = ILL_10G_RX_STATS_CLR,
	.lpbk_off = PHY_BASE_OFF + PHY_RX_SER_LOOP_BACK,
	.lpbk_en_val = 1,
	.link_off = PHY_BASE_OFF + PHY_RX_LOCKED_OFF,
	.link_mask = PHY_RX_LOCKED_DATA,
};

static const struct regmap_range regmap_range_10g[] = {
	regmap_reg_range(ILL_10G_BASE_OFF, ILL_10G_MAX_OFF),
	regmap_reg_range(PHY_BASE_OFF, PHY_BASE_OFF + PHY_MAX_OFF),
};

static const struct regmap_access_table access_table_10g = {
	.yes_ranges	= regmap_range_10g,
	.n_yes_ranges	= ARRAY_SIZE(regmap_range_10g),
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
	{STAT_INFO(0x962, "rx_frame_octets_ok")}
};

static const struct s10hssi_ops_params intel_ll_100g_params = {
	.stats = stats_100g,
	.num_stats = ARRAY_SIZE(stats_100g),
	.tx_clr_off = ILL_100G_TX_STATS_CLR,
	.rx_clr_off = ILL_100G_RX_STATS_CLR,
	.lpbk_off = ILL_100G_LPBK_OFF,
	.lpbk_en_val = ILL_100G_LPBK_EN_VAL,
};

static const struct regmap_range regmap_range_100g[] = {
	regmap_reg_range(ILL_100G_PHY_BASE_OFF, ILL_100G_PHY_MAX_OFF),
	regmap_reg_range(ILL_100G_BASE_OFF, ILL_100G_MAX_OFF),
	regmap_reg_range(ILL_100G_TX_FEC_OFF, ILL_100G_TX_FEC_MAX_OFF),
	regmap_reg_range(ILL_100G_RX_FEC_OFF, ILL_100G_RX_FEC_MAX_OFF),
};

static const struct regmap_access_table access_table_100g = {
	.yes_ranges	= regmap_range_100g,
	.n_yes_ranges	= ARRAY_SIZE(regmap_range_100g),
};

static void s10hssi_init_netdev(struct net_device *netdev)
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

static int s10hssi_mac_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct regmap_config cfg = {0};
	struct s10hssi_netdata *npriv;
	struct s10hssi_drvdata *priv;
	struct regmap *regmap;
	void __iomem *base;
	u64 val, pcs_speed;
	u32 flags;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);

	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);

	base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);

	if (!base)
		return -ENOMEM;

	priv->netdev = alloc_netdev(sizeof(struct s10hssi_netdata),
				    "s10hssi%d", NET_NAME_UNKNOWN,
				    s10hssi_init_netdev);

	if (!priv->netdev)
		return -ENOMEM;

	npriv = netdev_priv(priv->netdev);

	npriv->dfl_dev = dfl_dev;

	val = readq(base + CAPABILITY_OFF);

	dev_info(dev, "%s capability register 0x%llx\n", __func__, val);

	pcs_speed = FIELD_GET(CAP_CONTAINS_PCS, val);

	if (pcs_speed == CAP_RATE_10G) {
		dev_info(dev, "%s found 10G\n", __func__);
		npriv->ops_params = (struct s10hssi_ops_params *)&s10hssi_params;
		cfg.wr_table = &access_table_10g;
		cfg.rd_table = &access_table_10g;
		cfg.max_register = PHY_BASE_OFF + PHY_MAX_OFF;
	} else if (pcs_speed == CAP_RATE_100G) {
		dev_info(dev, "%s found 100G\n", __func__);
		npriv->ops_params = devm_kmalloc(dev, sizeof(*npriv->ops_params), GFP_KERNEL);
		if (!npriv->ops_params)
			return -ENOMEM;

		*npriv->ops_params = intel_ll_100g_params;
		if (FIELD_GET(CAP_CONTAINS_FEC, val)) {
			dev_info(dev, "%s contains FEC\n", __func__);
			npriv->ops_params->link_off = ILL_100G_RX_FEC_ST;
			npriv->ops_params->link_mask = ILL_100G_RX_FEC_ST_ALN;
		} else {
			dev_info(dev, "%s no FEC\n", __func__);
			npriv->ops_params->link_off = ILL_100G_RX_PCS_ALN_OFF;
			npriv->ops_params->link_mask = ILL_100G_RX_RCS_ALIGNED;
		}

		cfg.wr_table = &access_table_100g;
		cfg.rd_table = &access_table_100g;
		cfg.max_register = ILL_100G_RX_FEC_MAX_OFF;
	} else {
		dev_err(dev, "%s unsupported pcs data rate 0x%llx\n",
			__func__, pcs_speed);
		return -EINVAL;
	}

	cfg.reg_bits = 32;
	cfg.val_bits = 32;

	regmap = devm_regmap_init_indirect_register(dev, base + MB_BASE_OFF, &cfg);

	if (!regmap)
		return -ENOMEM;

	npriv->regmap = regmap;

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

	dev_info(&dfl_dev->dev, "setting carrier off\n");
	netif_carrier_off(priv->netdev);

	INIT_WORK(&priv->poll_workq, poll_work);
	timer_setup(&priv->poll_timer, poll_timerf, 0);
	mod_timer(&priv->poll_timer, jiffies + msecs_to_jiffies(1000));

	return ret;
}

static void s10hssi_mac_remove(struct dfl_device *dfl_dev)
{
	struct s10hssi_drvdata *priv = dev_get_drvdata(&dfl_dev->dev);

	unregister_netdev(priv->netdev);

	del_timer_sync(&priv->poll_timer);
}

#define FME_FEATURE_ID_LL_10G_MAC 0xf

static const struct dfl_device_id s10hssi_mac_ids[] = {
	{ FME_ID, FME_FEATURE_ID_LL_10G_MAC },
	{ }
};

static struct dfl_driver s10hssi_mac_driver = {
	.drv = {
		.name = "s10hssi",
	},
	.id_table = s10hssi_mac_ids,
	.probe = s10hssi_mac_probe,
	.remove = s10hssi_mac_remove,
};

module_dfl_driver(s10hssi_mac_driver);
MODULE_DEVICE_TABLE(dfl, s10hssi_mac_ids);
MODULE_DESCRIPTION("Network Device Driver for Intel(R) Startix10 HSSI");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
