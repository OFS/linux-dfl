// SPDX-License-Identifier: GPL-2.0
/*
 * PMCI-based interface to MAX10 BMC
 *
 * Copyright (C) 2020-2021 Intel Corporation, Inc.
 *
 */

#include <linux/dfl.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/regmap.h>

#define M10BMC_PMCI_INDIRECT_BASE 0x400

struct pmci_device {
	void __iomem *base;
	struct device *dev;
	struct intel_m10bmc m10bmc;
};

static const struct regmap_range m10bmc_pmci_regmap_range[] = {
	regmap_reg_range(M10BMC_PMCI_SYS_BASE, M10BMC_PMCI_SYS_END),
};

static const struct regmap_access_table m10_access_table = {
	.yes_ranges	= m10bmc_pmci_regmap_range,
	.n_yes_ranges	= ARRAY_SIZE(m10bmc_pmci_regmap_range),
};

static struct regmap_config m10bmc_pmci_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.wr_table = &m10_access_table,
	.rd_table = &m10_access_table,
	.max_register = M10BMC_PMCI_SYS_END,
};

static int pmci_probe(struct dfl_device *ddev)
{
	struct device *dev = &ddev->dev;
	struct pmci_device *pmci;

	pmci = devm_kzalloc(dev, sizeof(*pmci), GFP_KERNEL);
	if (!pmci)
		return -ENOMEM;

	pmci->m10bmc.dev = dev;
	pmci->dev = dev;
	pmci->m10bmc.type = M10_N6000;

	pmci->base = devm_ioremap_resource(dev, &ddev->mmio_res);
	if (IS_ERR(pmci->base))
		return PTR_ERR(pmci->base);

	pmci->m10bmc.regmap =
		devm_regmap_init_indirect_register(dev,
						   pmci->base + M10BMC_PMCI_INDIRECT_BASE,
						   &m10bmc_pmci_regmap_config);
	if (IS_ERR(pmci->m10bmc.regmap))
		return PTR_ERR(pmci->m10bmc.regmap);

	return m10bmc_dev_init(&pmci->m10bmc);
}

#define FME_FEATURE_ID_PMCI_BMC	0x12

static const struct dfl_device_id pmci_ids[] = {
	{ FME_ID, FME_FEATURE_ID_PMCI_BMC },
	{ }
};
MODULE_DEVICE_TABLE(dfl, pmci_ids);

static struct dfl_driver pmci_driver = {
	.drv	= {
		.name       = "intel-m10-bmc",
		.dev_groups = m10bmc_dev_groups,
	},
	.id_table = pmci_ids,
	.probe    = pmci_probe,
};

module_dfl_driver(pmci_driver);

MODULE_DESCRIPTION("MAX10 BMC PMCI-based interface");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
