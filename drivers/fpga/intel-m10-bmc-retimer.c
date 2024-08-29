// SPDX-License-Identifier: GPL-2.0
/* Intel Max10 BMC Retimer Interface Driver
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/device.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/platform_device.h>

#define NUM_CHIP	2
#define MAX_LINK	4

#define BITS_MASK(nbits)	((1 << (nbits)) - 1)

#define N3000BMC_RETIMER_DEV_NAME "n3000bmc-retimer"
#define M10BMC_RETIMER_MII_NAME "m10bmc retimer mii"

struct m10bmc_retimer {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	int num_devs;
	struct device *base_dev;
	struct mii_bus *retimer_mii_bus;
};

#define RETIMER_LINK_STAT_BIT(retimer_id, link_id) \
	BIT(((retimer_id) << 2) + (link_id))

static u32 retimer_get_link(struct m10bmc_retimer *retimer, int index)
{
	unsigned int val;

	if (m10bmc_sys_read(retimer->m10bmc, PKVL_LINK_STATUS, &val)) {
		dev_err(retimer->dev, "fail to read PKVL_LINK_STATUS\n");
		return 0;
	}

	if (val & BIT(index))
		return 1;

	return 0;
}

static int m10bmc_retimer_phy_match(struct phy_device *phydev)
{
	if (phydev->mdio.bus->name &&
	    !strcmp(phydev->mdio.bus->name, M10BMC_RETIMER_MII_NAME)) {
		return 1;
	}

	return 0;
}

static int m10bmc_retimer_phy_probe(struct phy_device *phydev)
{
	struct m10bmc_retimer *retimer = phydev->mdio.bus->priv;

	phydev->priv = retimer;

	return 0;
}

static void m10bmc_retimer_phy_remove(struct phy_device *phydev)
{
	if (phydev->attached_dev)
		phy_disconnect(phydev);
}

static int m10bmc_retimer_read_status(struct phy_device *phydev)
{
	struct m10bmc_retimer *retimer = phydev->priv;

	phydev->link = retimer_get_link(retimer, phydev->mdio.addr);

	phydev->duplex = DUPLEX_FULL;

	return 0;
}

static int m10bmc_retimer_get_features(struct phy_device *phydev)
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

static struct phy_driver m10bmc_retimer_phy_driver = {
	.phy_id			= 0xffffffff,
	.phy_id_mask		= 0xffffffff,
	.name			= "m10bmc retimer PHY",
	.match_phy_device	= m10bmc_retimer_phy_match,
	.probe			= m10bmc_retimer_phy_probe,
	.remove			= m10bmc_retimer_phy_remove,
	.read_status		= m10bmc_retimer_read_status,
	.get_features		= m10bmc_retimer_get_features,
	.read_mmd		= genphy_read_mmd_unsupported,
	.write_mmd		= genphy_write_mmd_unsupported,
};

static int m10bmc_retimer_read(struct mii_bus *bus, int addr, int regnum)
{
	struct m10bmc_retimer *retimer = bus->priv;

	if (addr < retimer->num_devs &&
	    (regnum == MII_PHYSID1 || regnum == MII_PHYSID2))
		return 0;

	return 0xffff;
}

static int m10bmc_retimer_write(struct mii_bus *bus, int addr, int regnum, u16 val)
{
	return 0;
}

static int m10bmc_retimer_mii_bus_init(struct m10bmc_retimer *retimer)
{
	struct mii_bus *bus;
	int ret;

	bus = devm_mdiobus_alloc(retimer->dev);
	if (!bus)
		return -ENOMEM;

	bus->priv = (void *)retimer;
	bus->name = M10BMC_RETIMER_MII_NAME;
	bus->read = m10bmc_retimer_read;
	bus->write = m10bmc_retimer_write;
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-mii",
		 dev_name(retimer->base_dev));
	bus->parent = retimer->dev;
	bus->phy_mask = ~(BITS_MASK(retimer->num_devs));

	ret = mdiobus_register(bus);
	if (ret)
		return ret;

	retimer->retimer_mii_bus = bus;

	return 0;
}

static void m10bmc_retimer_mii_bus_uinit(struct m10bmc_retimer *retimer)
{
	mdiobus_unregister(retimer->retimer_mii_bus);
}

static int intel_m10bmc_retimer_probe(struct platform_device *pdev)
{
	struct intel_m10bmc_retimer_pdata *pdata = dev_get_platdata(&pdev->dev);
	struct intel_m10bmc *m10bmc = dev_get_drvdata(pdev->dev.parent);
	struct m10bmc_retimer *retimer;

	retimer = devm_kzalloc(&pdev->dev, sizeof(*retimer), GFP_KERNEL);
	if (!retimer)
		return -ENOMEM;

	dev_set_drvdata(&pdev->dev, retimer);

	retimer->dev = &pdev->dev;
	retimer->m10bmc = m10bmc;
	retimer->base_dev = pdata->retimer_master;
	retimer->num_devs = NUM_CHIP * MAX_LINK;

	return m10bmc_retimer_mii_bus_init(retimer);
}

static int intel_m10bmc_retimer_remove(struct platform_device *pdev)
{
	struct m10bmc_retimer *retimer = dev_get_drvdata(&pdev->dev);

	m10bmc_retimer_mii_bus_uinit(retimer);

	return 0;
}

static struct platform_driver intel_m10bmc_retimer_driver = {
	.probe = intel_m10bmc_retimer_probe,
	.remove = intel_m10bmc_retimer_remove,
	.driver = {
		.name = N3000BMC_RETIMER_DEV_NAME,
	},
};

static int __init intel_m10bmc_retimer_init(void)
{
	int ret;

	ret = phy_driver_register(&m10bmc_retimer_phy_driver, THIS_MODULE);
	if (ret)
		return ret;

	return platform_driver_register(&intel_m10bmc_retimer_driver);
}
module_init(intel_m10bmc_retimer_init);

static void __exit intel_m10bmc_retimer_exit(void)
{
	platform_driver_unregister(&intel_m10bmc_retimer_driver);
	phy_driver_unregister(&m10bmc_retimer_phy_driver);
}
module_exit(intel_m10bmc_retimer_exit);

MODULE_ALIAS("platform:" N3000BMC_RETIMER_DEV_NAME);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX 10 BMC retimer driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(INTEL_M10_BMC_CORE);
