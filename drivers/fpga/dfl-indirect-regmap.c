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

#ifdef CONFIG_DEBUG_FS

static ssize_t user_buffer_to_uint(const char __user *buffer, size_t count,
				   loff_t *ppos, unsigned int *value)
{
	char buf[24];
	ssize_t len;
	int ret;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= sizeof(buf))
		return -ENOSPC;

	len = simple_write_to_buffer(buf, sizeof(buf) - 1,
				     ppos, buffer, count);
	if (len < 0)
		return len;

	buf[len] = '\0';
	ret = kstrtouint(buf, 16, value);
	if (ret)
		return -EIO;

	return len;
}

static ssize_t uint_to_user_buffer(char __user *buffer, size_t count,
				   loff_t *ppos, unsigned int value)
{
	char buf[24];
	int ret;

	if (*ppos != 0)
		return 0;

	ret = snprintf(buf, sizeof(buf) - 1, "0x%x\n", value);

	return simple_read_from_buffer(buffer, count, ppos, buf, ret);
}

static ssize_t regaddr_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *ppos)
{
	struct dfl_regmap_debug *debug = file->private_data;
	int ret;

	mutex_lock(&debug->lock);
	ret = user_buffer_to_uint(buffer, count, ppos, &debug->regaddr);
	mutex_unlock(&debug->lock);

	return ret;
}

static ssize_t regaddr_read(struct file *file, char __user *buffer,
			    size_t count, loff_t *ppos)
{
	struct dfl_regmap_debug *debug = file->private_data;
	int ret;

	mutex_lock(&debug->lock);
	ret =  uint_to_user_buffer(buffer, count, ppos, debug->regaddr);
	mutex_unlock(&debug->lock);

	return ret;
}

static const struct file_operations regaddr_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = regaddr_read,
	.write = regaddr_write,
};

static ssize_t regval_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	struct dfl_regmap_debug *debug = file->private_data;
	u32 val;
	int ret;

	ret = user_buffer_to_uint(buffer, count, ppos, &val);
	if (ret < 0)
		return ret;

	mutex_lock(&debug->lock);
	ret = regmap_write(debug->map, debug->regaddr, val);
	mutex_unlock(&debug->lock);

	return ret ?: count;
}

static ssize_t regval_read(struct file *file, char __user *buffer,
			   size_t count, loff_t *ppos)
{
	struct dfl_regmap_debug *debug = file->private_data;
	u32 val;
	int ret;

	mutex_lock(&debug->lock);
	ret = regmap_read(debug->map, debug->regaddr, &val);
	mutex_unlock(&debug->lock);
	if (ret)
		return ret;

	return uint_to_user_buffer(buffer, count, ppos, val);
}

static const struct file_operations regval_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = regval_read,
	.write = regval_write,
};

struct dfl_regmap_debug *dfl_regmap_debug_init(struct device *dev,
						 struct regmap *map)
{
	struct dfl_regmap_debug *debug;

	if (!dev || !map)
		return NULL;

	debug = devm_kzalloc(dev, sizeof(*debug), GFP_KERNEL);
	if (!debug)
		return NULL;

	debug->debugfs = debugfs_create_dir(dev_name(dev), NULL);
	if (!debug->debugfs) {
		dev_err(dev, "Failed to create max10 debugfs\n");
		return NULL;
	}

	mutex_init(&debug->lock);
	debug->map = map;

	if (!debugfs_create_file("regaddr", 0644, debug->debugfs,
				 debug, &regaddr_fops))
		goto err_out;

	if (!debugfs_create_file("regval", 0644, debug->debugfs,
				 debug, &regval_fops))
		goto err_out;

	return debug;

err_out:
	debugfs_remove_recursive(debug->debugfs);
	return NULL;
}
EXPORT_SYMBOL_GPL(dfl_regmap_debug_init);

void dfl_regmap_debug_exit(struct dfl_regmap_debug *debug)
{
	if (!debug)
		return;

	debugfs_remove_recursive(debug->debugfs);
	mutex_destroy(&debug->lock);
}
EXPORT_SYMBOL_GPL(dfl_regmap_debug_exit);

#else /* !CONFIG_DEBUG_FS */
struct dfl_regmap_debug *dfl_regmap_debug_init(struct device *dev,
						 struct regmap *map)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(dfl_regmap_debug_init);

void dfl_regmap_debug_exit(struct dfl_regmap_debug *debug)
{
}
EXPORT_SYMBOL_GPL(dfl_regmap_debug_exit);
#endif /* CONFIG_DEBUG_FS */


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
