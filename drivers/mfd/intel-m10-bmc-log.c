// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Secure Update Driver
 *
 * Copyright (C) 2021 Intel Corporation. All rights reserved.
 *
 */

#include <linux/bitfield.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/platform_device.h>

struct m10bmc_log {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	unsigned int freq_s;		/* update frequency in seconds */
	struct delayed_work dwork;
};

#define M10BMC_TIMESTAMP_FREQ   60	/* 60 seconds between updates */
#define TIME_LOW	GENMASK(31, 0)
#define TIME_HIGH	GENMASK(63, 32)
static void m10bmc_log_time_sync(struct work_struct *work)
{
	struct delayed_work *dwork;
	u32 time_high, time_low;
	struct m10bmc_log *log;
	s64 time_ns;
	int ret;

	dwork = to_delayed_work(work);
	log = container_of(dwork, struct m10bmc_log, dwork);

	time_ns = ktime_to_ns(ktime_get_real());
	time_low = (u32)FIELD_GET(TIME_LOW, time_ns);
	time_high = (u32)FIELD_GET(TIME_LOW, time_ns);
	ret = regmap_write(log->m10bmc->regmap, m10bmc_base(log->m10bmc) +
			   M10BMC_PMCI_TIME_HIGH, time_high);
	if (!ret)
		ret = regmap_write(log->m10bmc->regmap,
				   m10bmc_base(log->m10bmc) +
				   M10BMC_PMCI_TIME_LOW, time_low);
	if (ret)
		dev_err_once(log->dev,
			     "Failed to update BMC timestamp: %d\n", ret);

	schedule_delayed_work(&log->dwork, log->freq_s * HZ);
}

static ssize_t
time_sync_frequency_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct m10bmc_log *ddata = dev_get_drvdata(dev);
	unsigned int ret, old_freq = ddata->freq_s;

	ret = kstrtouint(buf, 0, &ddata->freq_s);
	if (ret)
		return ret;

	if (old_freq)
		cancel_delayed_work_sync(&ddata->dwork);

	if (ddata->freq_s)
		m10bmc_log_time_sync(&ddata->dwork.work);

	return count;
}

static ssize_t
time_sync_frequency_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct m10bmc_log *ddata = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u\n", ddata->freq_s);
}
static DEVICE_ATTR_RW(time_sync_frequency);

static ssize_t flash_bin_read(struct kobject *kobj, char *buf, u32 addr,
			      loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct m10bmc_log *ddata = dev_get_drvdata(dev);
	int ret;

	if (!ddata->m10bmc->ops.flash_read)
		return -ENODEV;

	ret = ddata->m10bmc->ops.flash_read(ddata->m10bmc, buf,
					  addr + off, count);
	if (ret) {
		dev_err(ddata->dev, "failed to read flash %x\n", addr);
		return -EIO;
	}

	return count;
}

static ssize_t
bmc_event_log_read(struct file *filp, struct kobject *kobj,
		   struct bin_attribute *bin_attr, char *buf,
		   loff_t off, size_t count)
{
	return flash_bin_read(kobj, buf, PMCI_ERROR_LOG_ADDR, off,
			      count);
}
static BIN_ATTR_RO(bmc_event_log, PMCI_ERROR_LOG_SIZE);

static ssize_t
fpga_image_directory_read(struct file *filp, struct kobject *kobj,
			  struct bin_attribute *bin_attr, char *buf,
			  loff_t off, size_t count)
{
	return flash_bin_read(kobj, buf, PMCI_FPGA_IMAGE_DIR_ADDR, off,
			      count);
}
static BIN_ATTR_RO(fpga_image_directory, PMCI_FPGA_IMAGE_DIR_SIZE);

static ssize_t bom_info_read(struct file *filp, struct kobject *kobj,
			     struct bin_attribute *bin_attr, char *buf,
			     loff_t off, size_t count)
{
	return flash_bin_read(kobj, buf, PMCI_BOM_INFO_ADDR, off,
			      count);
}
static BIN_ATTR_RO(bom_info, PMCI_BOM_INFO_SIZE);

static struct attribute *m10bmc_log_attrs[] = {
	&dev_attr_time_sync_frequency.attr,
	&bin_attr_bmc_event_log.attr,
	&bin_attr_fpga_image_directory.attr,
	&bin_attr_bom_info.attr,
	NULL,
};
ATTRIBUTE_GROUPS(m10bmc_log);

static int m10bmc_log_probe(struct platform_device *pdev)
{
	struct m10bmc_log *ddata;

	ddata = devm_kzalloc(&pdev->dev, sizeof(*ddata), GFP_KERNEL);
	if (!ddata)
		return -ENOMEM;

	ddata->dev = &pdev->dev;
	ddata->m10bmc = dev_get_drvdata(pdev->dev.parent);
	ddata->freq_s = M10BMC_TIMESTAMP_FREQ;
	INIT_DELAYED_WORK(&ddata->dwork, m10bmc_log_time_sync);
	dev_set_drvdata(&pdev->dev, ddata);

	m10bmc_log_time_sync(&ddata->dwork.work);

	return 0;
}

static int m10bmc_log_remove(struct platform_device *pdev)
{
	struct m10bmc_log *ddata = dev_get_drvdata(&pdev->dev);

	cancel_delayed_work_sync(&ddata->dwork);
	return 0;
}

static struct platform_driver intel_m10bmc_log_driver = {
	.probe = m10bmc_log_probe,
	.remove = m10bmc_log_remove,
	.driver = {
		.name = "n6010bmc-log",
		.dev_groups = m10bmc_log_groups,
	},
};
module_platform_driver(intel_m10bmc_log_driver);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Log");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:intel-m10bmc-log");
