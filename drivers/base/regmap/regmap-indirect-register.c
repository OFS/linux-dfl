// SPDX-License-Identifier: GPL-2.0
/*
 * Indirect Register Access.
 *
 * Copyright (C) 2020 Intel Corporation, Inc.
 */
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define INDIRECT_CMD_OFF	0
#define INDIRECT_CMD_CLR	0
#define INDIRECT_CMD_RD		BIT(0)
#define INDIRECT_CMD_WR		BIT(1)
#define INDIRECT_CMD_ACK	BIT(2)

#define INDIRECT_ADDR_OFF	0x4
#define INDIRECT_RD_OFF		0x8
#define INDIRECT_WR_OFF		0xc

#define INDIRECT_INT_US		1
#define INDIRECT_TIMEOUT_US	10000

struct indirect_ctx {
	void __iomem *base;
	struct device *dev;
};

static int indirect_bus_clear_cmd(struct indirect_ctx *ctx)
{
	unsigned int cmd;
	int ret;

	writel(INDIRECT_CMD_CLR, ctx->base + INDIRECT_CMD_OFF);

	ret = readl_poll_timeout(ctx->base + INDIRECT_CMD_OFF, cmd,
				 cmd == INDIRECT_CMD_CLR,
				 INDIRECT_INT_US, INDIRECT_TIMEOUT_US);
	if (ret)
		dev_err(ctx->dev, "timed out waiting clear cmd (residual cmd=0x%x)\n", cmd);

	return ret;
}

static int indirect_bus_reg_read(void *context, unsigned int reg, unsigned int *val)
{
	struct indirect_ctx *ctx = context;
	unsigned int cmd, ack, tmpval;
	int ret, ret2;

	cmd = readl(ctx->base + INDIRECT_CMD_OFF);
	if (cmd != INDIRECT_CMD_CLR)
		dev_warn(ctx->dev, "residual cmd 0x%x on read entry\n", cmd);

	writel(reg, ctx->base + INDIRECT_ADDR_OFF);
	writel(INDIRECT_CMD_RD, ctx->base + INDIRECT_CMD_OFF);

	ret = readl_poll_timeout(ctx->base + INDIRECT_CMD_OFF, ack,
				 (ack & INDIRECT_CMD_ACK) == INDIRECT_CMD_ACK,
				 INDIRECT_INT_US, INDIRECT_TIMEOUT_US);
	if (ret)
		dev_err(ctx->dev, "read timed out on reg 0x%x ack 0x%x\n", reg, ack);
	else
		tmpval = readl(ctx->base + INDIRECT_RD_OFF);

	ret2 = indirect_bus_clear_cmd(ctx);

	if (ret)
		return ret;
	if (ret2)
		return ret2;

	*val = tmpval;
	return 0;
}

static int indirect_bus_reg_write(void *context, unsigned int reg, unsigned int val)
{
	struct indirect_ctx *ctx = context;
	unsigned int cmd, ack;
	int ret, ret2;

	cmd = readl(ctx->base + INDIRECT_CMD_OFF);
	if (cmd != INDIRECT_CMD_CLR)
		dev_warn(ctx->dev, "residual cmd 0x%x on write entry\n", cmd);

	writel(val, ctx->base + INDIRECT_WR_OFF);
	writel(reg, ctx->base + INDIRECT_ADDR_OFF);
	writel(INDIRECT_CMD_WR, ctx->base + INDIRECT_CMD_OFF);

	ret = readl_poll_timeout(ctx->base + INDIRECT_CMD_OFF, ack,
				 (ack & INDIRECT_CMD_ACK) == INDIRECT_CMD_ACK,
				 INDIRECT_INT_US, INDIRECT_TIMEOUT_US);
	if (ret)
		dev_err(ctx->dev, "write timed out on reg 0x%x ack 0x%x\n", reg, ack);

	ret2 = indirect_bus_clear_cmd(ctx);

	if (ret)
		return ret;
	return ret2;
}

static const struct regmap_bus indirect_bus = {
	.reg_write = indirect_bus_reg_write,
	.reg_read =  indirect_bus_reg_read,
};

/**
 * devm_regmap_init_indirect_register - create a regmap for indirect register access
 * @dev: device creating the regmap
 * @base: __iomem point to base of memory with mailbox
 * @cfg: regmap_config describing interface
 *
 * Return: 0 on success, negative error code otherwise.
 */
struct regmap *devm_regmap_init_indirect_register(struct device *dev,
						  void __iomem *base,
						  struct regmap_config *cfg)
{
	struct indirect_ctx *ctx;

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return NULL;

	ctx->base = base;
	ctx->dev = dev;

	/* Reset any previous commands */
	indirect_bus_clear_cmd(ctx);

	return devm_regmap_init(dev, &indirect_bus, ctx, cfg);
}
EXPORT_SYMBOL_GPL(devm_regmap_init_indirect_register);

MODULE_DESCRIPTION("Indirect Register Access");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
