// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for FPGA Management Engine Error Management
 *
 * Copyright 2019 Intel Corporation, Inc.
 *
 * Authors:
 *   Kang Luwei <luwei.kang@intel.com>
 *   Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *   Wu Hao <hao.wu@intel.com>
 *   Joseph Grecco <joe.grecco@intel.com>
 *   Enno Luebbers <enno.luebbers@intel.com>
 *   Tim Whisonant <tim.whisonant@intel.com>
 *   Ananda Ravuri <ananda.ravuri@intel.com>
 *   Mitchel, Henry <henry.mitchel@intel.com>
 */

#include <linux/uaccess.h>
#include <linux/fpga-dfl.h>

#include "dfl.h"
#include "dfl-fme.h"

#define FME_ERROR_MASK		0x8
#define FME_ERROR		0x10
#define MBP_ERROR		BIT_ULL(6)
#define PCIE0_ERROR_MASK	0x18
#define PCIE0_ERROR		0x20
#define PCIE1_ERROR_MASK	0x28
#define PCIE1_ERROR		0x30
#define FME_FIRST_ERROR		0x38
#define FME_NEXT_ERROR		0x40
#define RAS_NONFAT_ERROR_MASK	0x48
#define RAS_NONFAT_ERROR	0x50
#define RAS_CATFAT_ERROR_MASK	0x58
#define RAS_CATFAT_ERROR	0x60
#define RAS_ERROR_INJECT	0x68
#define INJECT_ERROR_MASK	GENMASK_ULL(2, 0)

#define ERROR_MASK		GENMASK_ULL(63, 0)

static ssize_t pcie0_errors_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 value;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	value = readq(base + PCIE0_ERROR);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n", (unsigned long long)value);
}

static ssize_t pcie0_errors_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	int ret = 0;
	u64 v, val;

	if (kstrtou64(buf, 0, &val))
		return -EINVAL;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	writeq(GENMASK_ULL(63, 0), base + PCIE0_ERROR_MASK);

	v = readq(base + PCIE0_ERROR);
	if (val == v)
		writeq(v, base + PCIE0_ERROR);
	else
		ret = -EINVAL;

	writeq(0ULL, base + PCIE0_ERROR_MASK);
	mutex_unlock(&pdata->lock);
	return ret ? ret : count;
}
static DEVICE_ATTR_RW(pcie0_errors);

static ssize_t pcie1_errors_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 value;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	value = readq(base + PCIE1_ERROR);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n", (unsigned long long)value);
}

static ssize_t pcie1_errors_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	int ret = 0;
	u64 v, val;

	if (kstrtou64(buf, 0, &val))
		return -EINVAL;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	writeq(GENMASK_ULL(63, 0), base + PCIE1_ERROR_MASK);

	v = readq(base + PCIE1_ERROR);
	if (val == v)
		writeq(v, base + PCIE1_ERROR);
	else
		ret = -EINVAL;

	writeq(0ULL, base + PCIE1_ERROR_MASK);
	mutex_unlock(&pdata->lock);
	return ret ? ret : count;
}
static DEVICE_ATTR_RW(pcie1_errors);

static ssize_t nonfatal_errors_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	void __iomem *base;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	return sprintf(buf, "0x%llx\n",
		       (unsigned long long)readq(base + RAS_NONFAT_ERROR));
}
static DEVICE_ATTR_RO(nonfatal_errors);

static ssize_t catfatal_errors_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	void __iomem *base;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	return sprintf(buf, "0x%llx\n",
		       (unsigned long long)readq(base + RAS_CATFAT_ERROR));
}
static DEVICE_ATTR_RO(catfatal_errors);

static ssize_t inject_errors_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 v;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	v = readq(base + RAS_ERROR_INJECT);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n",
		       (unsigned long long)FIELD_GET(INJECT_ERROR_MASK, v));
}

static ssize_t inject_errors_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u8 inject_error;
	u64 v;

	if (kstrtou8(buf, 0, &inject_error))
		return -EINVAL;

	if (inject_error & ~INJECT_ERROR_MASK)
		return -EINVAL;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	v = readq(base + RAS_ERROR_INJECT);
	v &= ~INJECT_ERROR_MASK;
	v |= FIELD_PREP(INJECT_ERROR_MASK, inject_error);
	writeq(v, base + RAS_ERROR_INJECT);
	mutex_unlock(&pdata->lock);

	return count;
}
static DEVICE_ATTR_RW(inject_errors);

static ssize_t fme_errors_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 value;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	value = readq(base + FME_ERROR);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n", (unsigned long long)value);
}

static ssize_t fme_errors_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 v, val;
	int ret = 0;

	if (kstrtou64(buf, 0, &val))
		return -EINVAL;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	writeq(GENMASK_ULL(63, 0), base + FME_ERROR_MASK);

	v = readq(base + FME_ERROR);
	if (val == v)
		writeq(v, base + FME_ERROR);
	else
		ret = -EINVAL;

	/* Workaround: disable MBP_ERROR if feature revision is 0 */
	writeq(dfl_feature_revision(base) ? 0ULL : MBP_ERROR,
	       base + FME_ERROR_MASK);
	mutex_unlock(&pdata->lock);
	return ret ? ret : count;
}
static DEVICE_ATTR_RW(fme_errors);

static ssize_t first_error_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 value;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	value = readq(base + FME_FIRST_ERROR);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n", (unsigned long long)value);
}
static DEVICE_ATTR_RO(first_error);

static ssize_t next_error_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;
	u64 value;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);
	value = readq(base + FME_NEXT_ERROR);
	mutex_unlock(&pdata->lock);

	return sprintf(buf, "0x%llx\n", (unsigned long long)value);
}
static DEVICE_ATTR_RO(next_error);

static struct attribute *fme_global_err_attrs[] = {
	&dev_attr_pcie0_errors.attr,
	&dev_attr_pcie1_errors.attr,
	&dev_attr_nonfatal_errors.attr,
	&dev_attr_catfatal_errors.attr,
	&dev_attr_inject_errors.attr,
	&dev_attr_fme_errors.attr,
	&dev_attr_first_error.attr,
	&dev_attr_next_error.attr,
	NULL,
};

static umode_t fme_global_err_attrs_visible(struct kobject *kobj,
					    struct attribute *attr, int n)
{
	struct device *dev = kobj_to_dev(kobj);

	/*
	 * sysfs entries are visible only if related private feature is
	 * enumerated.
	 */
	if (!dfl_get_feature_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR))
		return 0;

	return attr->mode;
}

const struct attribute_group fme_global_err_group = {
	.name       = "errors",
	.attrs      = fme_global_err_attrs,
	.is_visible = fme_global_err_attrs_visible,
};

static void fme_err_mask(struct device *dev, bool mask)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(dev);
	void __iomem *base;

	base = dfl_get_feature_ioaddr_by_id(dev, FME_FEATURE_ID_GLOBAL_ERR);

	mutex_lock(&pdata->lock);

	/* Workaround: keep MBP_ERROR always masked if revision is 0 */
	if (dfl_feature_revision(base))
		writeq(mask ? ERROR_MASK : 0, base + FME_ERROR_MASK);
	else
		writeq(mask ? ERROR_MASK : MBP_ERROR, base + FME_ERROR_MASK);

	writeq(mask ? ERROR_MASK : 0, base + PCIE0_ERROR_MASK);
	writeq(mask ? ERROR_MASK : 0, base + PCIE1_ERROR_MASK);
	writeq(mask ? ERROR_MASK : 0, base + RAS_NONFAT_ERROR_MASK);
	writeq(mask ? ERROR_MASK : 0, base + RAS_CATFAT_ERROR_MASK);

	mutex_unlock(&pdata->lock);
}

static int fme_global_err_init(struct platform_device *pdev,
			       struct dfl_feature *feature)
{
	fme_err_mask(&pdev->dev, false);

	return 0;
}

static void fme_global_err_uinit(struct platform_device *pdev,
				 struct dfl_feature *feature)
{
	fme_err_mask(&pdev->dev, true);
}

static long
fme_global_err_get_num_irqs(struct platform_device *pdev,
			    struct dfl_feature *feature, unsigned long arg)
{
	if (copy_to_user((void __user *)arg, &feature->nr_irqs,
			 sizeof(feature->nr_irqs)))
		return -EFAULT;

	return 0;
}

static long
fme_global_err_set_irq(struct platform_device *pdev,
		       struct dfl_feature *feature, unsigned long arg)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&pdev->dev);
	struct dfl_fpga_irq_set hdr;
	s32 *fds;
	long ret;

	if (!feature->nr_irqs)
		return -ENOENT;

	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
		return -EFAULT;

	if (!hdr.count || (hdr.start + hdr.count > feature->nr_irqs) ||
	    (hdr.start + hdr.count < hdr.start))
		return -EINVAL;

	fds = memdup_user((void __user *)(arg + sizeof(hdr)),
			  hdr.count * sizeof(s32));
	if (IS_ERR(fds))
		return PTR_ERR(fds);

	mutex_lock(&pdata->lock);
	ret = dfl_fpga_set_irq_triggers(feature, hdr.start, hdr.count, fds);
	mutex_unlock(&pdata->lock);

	kfree(fds);
	return ret;
}

static long
fme_global_error_ioctl(struct platform_device *pdev,
		       struct dfl_feature *feature,
		       unsigned int cmd, unsigned long arg)
{
	long ret = -ENODEV;

	switch (cmd) {
	case DFL_FPGA_FME_ERR_GET_IRQ_NUM:
		ret = fme_global_err_get_num_irqs(pdev, feature, arg);
		break;
	case DFL_FPGA_FME_ERR_SET_IRQ:
		ret = fme_global_err_set_irq(pdev, feature, arg);
		break;
	default:
		dev_dbg(&pdev->dev, "%x cmd not handled", cmd);
	}

	return ret;
}

const struct dfl_feature_id fme_global_err_id_table[] = {
	{.id = FME_FEATURE_ID_GLOBAL_ERR,},
	{0,}
};

const struct dfl_feature_ops fme_global_err_ops = {
	.init = fme_global_err_init,
	.uinit = fme_global_err_uinit,
	.ioctl = fme_global_error_ioctl,
};
