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

#define PMCI_M10BMC_INDIRECT_BASE 0x100

#define PMCI_FLASH_CTRL 0x40
#define PMCI_FLASH_WR_MODE BIT(0)
#define PMCI_FLASH_RD_MODE BIT(1)
#define PMCI_FLASH_BUSY    BIT(2)
#define PMCI_FLASH_FIFO_SPACE GENMASK(13, 4)
#define PMCI_FLASH_READ_COUNT GENMASK(25, 16)

#define PMCI_FLASH_INT_US       1
#define PMCI_FLASH_TIMEOUT_US   10000

#define PMCI_FLASH_ADDR 0x44
#define PMCI_FLASH_FIFO 0x800
#define PMCI_READ_BLOCK_SIZE 0x800

struct pmci_device {
	void __iomem *base;
	struct device *dev;
	struct intel_m10bmc m10bmc;
};

static u32
pmci_get_write_space(struct pmci_device *pmci, u32 size)
{
	u32 count, val;
	int ret;

	ret = read_poll_timeout(readl, val,
				FIELD_GET(PMCI_FLASH_FIFO_SPACE, val) != 0,
				PMCI_FLASH_INT_US, PMCI_FLASH_TIMEOUT_US,
				false, pmci->base + PMCI_FLASH_CTRL);
	if (ret == -ETIMEDOUT)
		return 0;

	count = FIELD_GET(PMCI_FLASH_FIFO_SPACE, val) * 4;

	return (size > count) ? count : size;
}

static int
pmci_flash_bulk_write(struct intel_m10bmc *m10bmc, void *buf, u32 size)
{
	struct pmci_device *pmci = container_of(m10bmc, struct pmci_device, m10bmc);
	u32 blk_size, n_offset = 0;

	while (size) {
		blk_size = pmci_get_write_space(pmci, size);
		if (blk_size == 0) {
			dev_err(pmci->dev, "get FIFO available size fail\n");
			return -EIO;
		}
		size -= blk_size;
		memcpy_toio(pmci->base + PMCI_FLASH_FIFO, buf + n_offset, blk_size);
		n_offset += blk_size;
	}

	return 0;
}

static int
pmci_flash_bulk_read(struct intel_m10bmc *m10bmc, void *buf,
		     u32 addr, u32 size)
{
	struct pmci_device *pmci = container_of(m10bmc, struct pmci_device, m10bmc);
	u32 blk_size, offset = 0, val;
	int ret;

	if (!IS_ALIGNED(addr, 4))
		return -EINVAL;

	while (size) {
		blk_size = min_t(u32, size, PMCI_READ_BLOCK_SIZE);

		writel(addr + offset, pmci->base + PMCI_FLASH_ADDR);

		writel(FIELD_PREP(PMCI_FLASH_READ_COUNT, blk_size / 4)
				| PMCI_FLASH_RD_MODE,
			pmci->base + PMCI_FLASH_CTRL);

		ret = readl_poll_timeout((pmci->base + PMCI_FLASH_CTRL), val,
					 !(val & PMCI_FLASH_BUSY),
					 PMCI_FLASH_INT_US, PMCI_FLASH_TIMEOUT_US);
		if (ret) {
			dev_err(pmci->dev, "%s timed out on reading flash 0x%xn",
				__func__, val);
			return ret;
		}

		memcpy_fromio(buf, pmci->base + PMCI_FLASH_FIFO, blk_size);

		size -= blk_size;
		offset += blk_size;
	}

	writel(0, pmci->base + PMCI_FLASH_CTRL);

	return 0;
}

static const struct regmap_range m10_regmap_range[] = {
	regmap_reg_range(PMCI_M10BMC_SYS_BASE, PMCI_M10BMC_SYS_END),
};

static const struct regmap_access_table m10_access_table = {
	.yes_ranges	= m10_regmap_range,
	.n_yes_ranges	= ARRAY_SIZE(m10_regmap_range),
};

static struct regmap_config pmci_max10_cfg = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.fast_io = true,
	.wr_table = &m10_access_table,
	.rd_table = &m10_access_table,
	.max_register = PMCI_M10BMC_SYS_END,
};

static int pmci_probe(struct dfl_device *ddev)
{
	struct fpga_flash_ops *pmci_flash_ops;
	struct device *dev = &ddev->dev;
	struct pmci_device *pmci;

	pmci = devm_kzalloc(dev, sizeof(*pmci), GFP_KERNEL);
	if (!pmci)
		return -ENOMEM;

	pmci_flash_ops = devm_kzalloc(dev, sizeof(*pmci_flash_ops), GFP_KERNEL);
	if (!pmci_flash_ops)
		return -ENOMEM;

	pmci_flash_ops->read_blk = pmci_flash_bulk_read;
	pmci_flash_ops->write_blk = pmci_flash_bulk_write;

	pmci->m10bmc.dev = dev;
	pmci->dev = dev;
	pmci->m10bmc.type = M10_PMCI;
	pmci->m10bmc.flash_ops = pmci_flash_ops;

	pmci->base = devm_ioremap_resource(dev, &ddev->mmio_res);
	if (IS_ERR(pmci->base))
		return PTR_ERR(pmci->base);

	pmci->m10bmc.regmap =
		devm_regmap_init_indirect_register(dev,
						   pmci->base + PMCI_M10BMC_INDIRECT_BASE,
						   &pmci_max10_cfg);
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
