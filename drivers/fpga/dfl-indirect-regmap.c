// SPDX-License-Identifier: GPL-2.0
/*
 * FPGA Device Feature List (DFL) Mailbox Regmap Support
 *
 * Copyright (C) 2020 Intel Corporation, Inc.
 */
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/fpga/dfl-bus.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/device.h>

#define DFL_INDIRECT_CMD_OFF	0x0
#define DFL_INDIRECT_CMD_RD	BIT(0)
#define DFL_INDIRECT_CMD_WR	BIT(1)
#define DFL_INDIRECT_CMD_ACK	BIT(2)

#define DFL_INDIRECT_ADDR_OFF	0x4
#define DFL_INDIRECT_RD_OFF	0x8
#define DFL_INDIRECT_WR_OFF	0xc

#define DFL_INDIRECT_INT_US	1
#define DFL_INDIRECT_TIMEOUT_US	10000

struct dfl_indirect_ctx {
	void __iomem *base;
	struct device *dev;
};

static int dfl_indirect_bus_clr_cmd(struct dfl_indirect_ctx *ctx)
{
	unsigned int cmd;
	int ret;

	writel(0, ctx->base + DFL_INDIRECT_CMD_OFF);

	ret = readl_poll_timeout((ctx->base + DFL_INDIRECT_CMD_OFF), cmd,
				 (!cmd), DFL_INDIRECT_INT_US, DFL_INDIRECT_TIMEOUT_US);

	if (ret)
		dev_err(ctx->dev, "%s timed out on clearing cmd 0x%xn", __func__, cmd);

	return ret;
}

static int dfl_indirect_bus_reg_read(void *context, unsigned int reg,
				     unsigned int *val)
{
	struct dfl_indirect_ctx *ctx = context;
	unsigned int cmd;
	int ret;

	cmd = readl(ctx->base + DFL_INDIRECT_CMD_OFF);

	if (cmd)
		dev_warn(ctx->dev, "%s non-zero cmd 0x%x\n", __func__, cmd);

	writel(reg, ctx->base + DFL_INDIRECT_ADDR_OFF);

	writel(DFL_INDIRECT_CMD_RD, ctx->base + DFL_INDIRECT_CMD_OFF);

	ret = readl_poll_timeout((ctx->base + DFL_INDIRECT_CMD_OFF), cmd,
				 (cmd & DFL_INDIRECT_CMD_ACK), DFL_INDIRECT_INT_US,
				 DFL_INDIRECT_TIMEOUT_US);

	*val = readl(ctx->base + DFL_INDIRECT_RD_OFF);

	if (ret)
		dev_err(ctx->dev, "%s timed out on reg 0x%x cmd 0x%x\n", __func__, reg, cmd);

	if (dfl_indirect_bus_clr_cmd(ctx))
		ret = -ETIME;

	return ret;
}

static int dfl_indirect_bus_reg_write(void *context, unsigned int reg,
				      unsigned int val)
{
	struct dfl_indirect_ctx *ctx = context;
	unsigned int cmd;
	int ret;

	cmd = readl(ctx->base + DFL_INDIRECT_CMD_OFF);

	if (cmd)
		dev_warn(ctx->dev, "%s non-zero cmd 0x%x\n", __func__, cmd);

	writel(val, ctx->base + DFL_INDIRECT_WR_OFF);

	writel(reg, ctx->base + DFL_INDIRECT_ADDR_OFF);

	writel(DFL_INDIRECT_CMD_WR, ctx->base + DFL_INDIRECT_CMD_OFF);

	ret = readl_poll_timeout((ctx->base + DFL_INDIRECT_CMD_OFF), cmd,
				 (cmd & DFL_INDIRECT_CMD_ACK), DFL_INDIRECT_INT_US,
				 DFL_INDIRECT_TIMEOUT_US);

	if (ret)
		dev_err(ctx->dev, "%s timed out on reg 0x%x cmd 0x%x\n", __func__, reg, cmd);

	if (dfl_indirect_bus_clr_cmd(ctx))
		ret = -ETIME;

	return ret;
}

static const struct regmap_bus indirect_bus = {
	.fast_io = true,
	.reg_read = dfl_indirect_bus_reg_read,
	.reg_write = dfl_indirect_bus_reg_write,
};

/**
 * dfl_indirect_regmap_init - create a regmap for a dfl mailbox
 * @dev: device creating the regmap
 * @base: __iomem point to base of memory with mailbox
 * @off: offset into base that starts the mailbox
 *
 * Return: 0 on success, negative error code otherwise.
 */
struct regmap *dfl_indirect_regmap_init(struct device *dev, void __iomem *base, struct regmap_config *cfg)
{
	struct dfl_indirect_ctx *ctx;

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return NULL;

	ctx->base = base;
	ctx->dev = dev;

	return devm_regmap_init(dev, &indirect_bus, ctx, cfg);
}
EXPORT_SYMBOL_GPL(dfl_indirect_regmap_init);

MODULE_DESCRIPTION("DFL mailbox regmap support");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
