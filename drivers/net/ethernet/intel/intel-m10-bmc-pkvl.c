// SPDX-License-Identifier: GPL-2.0
/* Intel Max10 BMC Parkvale Interface Driver
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/device.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/platform_device.h>

#include "dfl-eth-group.h"

#define NUM_CHIP	2
#define MAX_LINK	4

#define BITS_MASK(nbits)	((1 << (nbits)) - 1)

#define N3000BMC_PKVL_DEV_NAME "n3000bmc-pkvl"
#define N3000_PKVL_MII_NAME "n3000 pkvl mii"

struct n3000bmc_pkvl {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	int num_devs;
	struct device *base_dev;
	struct mii_bus *pkvl_mii_bus;
};

#define PKVL_LINK_STAT_BIT(pkvl_id, link_id) \
	BIT(((pkvl_id) << 2) + (link_id))

static u32 pkvl_get_link(struct n3000bmc_pkvl *pkvl, int index)
{
	unsigned int val;

	if (m10bmc_sys_read(pkvl->m10bmc, PKVL_LINK_STATUS, &val)) {
		dev_err(pkvl->dev, "fail to read PKVL_LINK_STATUS\n");
		return 0;
	}

	if (val & BIT(index))
		return 1;

	return 0;
}

static int n3000_pkvl_phy_match(struct phy_device *phydev)
{
	if (phydev->mdio.bus->name &&
	    !strcmp(phydev->mdio.bus->name, N3000_PKVL_MII_NAME)) {
		return 1;
	}

	return 0;
}

static int n3000_pkvl_phy_probe(struct phy_device *phydev)
{
	struct n3000bmc_pkvl *pkvl = phydev->mdio.bus->priv;

	phydev->priv = pkvl;

	return 0;
}

static int n3000_pkvl_phy_read_status(struct phy_device *phydev)
{
	struct n3000bmc_pkvl *pkvl = phydev->priv;

	phydev->link = pkvl_get_link(pkvl, phydev->mdio.addr);

	phydev->duplex = DUPLEX_FULL;

	return 0;
}

static int n3000_pkvl_phy_get_features(struct phy_device *phydev)
{
	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT,
			 phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,
			 phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,
			 phydev->supported);

	linkmode_set_bit(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
			 phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,
			 phydev->supported);

	linkmode_set_bit(ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
			 phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
			 phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,
			 phydev->supported);

	linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, phydev->supported);

	return 0;
}

static struct phy_driver n3000_pkvl_phy_driver = {
	.phy_id			= 0xffffffff,
	.phy_id_mask		= 0xffffffff,
	.name			= "N3000 pkvl PHY",
	.match_phy_device	= n3000_pkvl_phy_match,
	.probe			= n3000_pkvl_phy_probe,
	.read_status		= n3000_pkvl_phy_read_status,
	.get_features		= n3000_pkvl_phy_get_features,
	.read_mmd		= genphy_read_mmd_unsupported,
	.write_mmd		= genphy_write_mmd_unsupported,
};

static int pkvl_phy_read(struct mii_bus *bus, int addr, int regnum)
{
	struct n3000bmc_pkvl *pkvl = bus->priv;

	if (addr < pkvl->num_devs &&
	    (regnum == MII_PHYSID1 || regnum == MII_PHYSID2))
		return 0;

	return 0xffff;
}

static int pkvl_phy_write(struct mii_bus *bus, int addr, int regnum, u16 val)
{
	return 0;
}

static int pkvl_mii_bus_init(struct n3000bmc_pkvl *pkvl)
{
	struct mii_bus *bus;
	int ret;

	bus = devm_mdiobus_alloc(pkvl->dev);
	if (!bus)
		return -ENOMEM;

	bus->priv = (void *)pkvl;
	bus->name = N3000_PKVL_MII_NAME;
	bus->read = pkvl_phy_read;
	bus->write = pkvl_phy_write;
	snprintf(bus->id, MII_BUS_ID_SIZE, DFL_ETH_MII_ID_FMT,
		 dev_name(pkvl->base_dev));
	bus->parent = pkvl->dev;
	bus->phy_mask = ~(BITS_MASK(pkvl->num_devs));

	ret = mdiobus_register(bus);
	if (ret)
		return ret;

	pkvl->pkvl_mii_bus = bus;

	return 0;
}

static void pkvl_mii_bus_uinit(struct n3000bmc_pkvl *pkvl)
{
	mdiobus_unregister(pkvl->pkvl_mii_bus);
}

static int m10bmc_pkvl_probe(struct platform_device *pdev)
{
	struct intel_m10bmc_pkvl_pdata *pdata = dev_get_platdata(&pdev->dev);
	struct intel_m10bmc *m10bmc = dev_get_drvdata(pdev->dev.parent);
	struct n3000bmc_pkvl *pkvl;

	pkvl = devm_kzalloc(&pdev->dev, sizeof(*pkvl), GFP_KERNEL);
	if (!pkvl)
		return -ENOMEM;

	dev_set_drvdata(&pdev->dev, pkvl);

	pkvl->dev = &pdev->dev;
	pkvl->m10bmc = m10bmc;
	pkvl->base_dev = pdata->pkvl_master;
	pkvl->num_devs = NUM_CHIP * MAX_LINK;

	return pkvl_mii_bus_init(pkvl);
}

static int m10bmc_pkvl_remove(struct platform_device *pdev)
{
	struct n3000bmc_pkvl *pkvl = dev_get_drvdata(&pdev->dev);

	pkvl_mii_bus_uinit(pkvl);

	return 0;
}

static struct platform_driver intel_m10bmc_pkvl_driver = {
	.probe = m10bmc_pkvl_probe,
	.remove = m10bmc_pkvl_remove,
	.driver = {
		.name = N3000BMC_PKVL_DEV_NAME,
	},
};

static int __init intel_m10bmc_pkvl_init(void)
{
	int ret;

	ret = phy_driver_register(&n3000_pkvl_phy_driver, THIS_MODULE);
	if (ret)
		return ret;

	return platform_driver_register(&intel_m10bmc_pkvl_driver);
}
module_init(intel_m10bmc_pkvl_init);

static void __exit intel_m10bmc_pkvl_exit(void)
{
	platform_driver_unregister(&intel_m10bmc_pkvl_driver);
	phy_driver_unregister(&n3000_pkvl_phy_driver);
}
module_exit(intel_m10bmc_pkvl_exit);

MODULE_ALIAS("platform:" N3000BMC_PKVL_DEV_NAME);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Parkvale Interface");
MODULE_LICENSE("GPL");
