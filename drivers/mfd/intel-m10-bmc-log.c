// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 Board Management Controller Log Driver
 *
 * Copyright (C) 2021-2023 Intel Corporation.
 */

#include <linux/bitfield.h>
#include <linux/dev_printk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/nvmem-provider.h>
#include <linux/mod_devicetable.h>
#include <linux/types.h>

#include <linux/mfd/intel-m10-bmc.h>

#define M10BMC_TIMESTAMP_FREQ			60	/* 60 secs between updates */

struct m10bmc_log_cfg {
	int el_size;
	unsigned long el_off;

	int id_size;
	unsigned long id_off;

	int bi_size;
	unsigned long bi_off;
};

struct m10bmc_log {
	struct device *dev;
	struct intel_m10bmc *m10bmc;
	unsigned int freq_s;		/* update frequency in seconds */
	struct delayed_work dwork;
	const struct m10bmc_log_cfg *log_cfg;
	struct nvmem_device *bmc_event_log_nvmem;
	struct nvmem_device *fpga_image_dir_nvmem;
	struct nvmem_device *bom_info_nvmem;
};

static void m10bmc_log_time_sync(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	const struct m10bmc_csr_map *csr_map;
	struct m10bmc_log *log;
	s64 time_ms;
	int ret;

	log = container_of(dwork, struct m10bmc_log, dwork);
	csr_map = log->m10bmc->info->csr_map;

	time_ms = ktime_to_ms(ktime_get_real());
	ret = regmap_write(log->m10bmc->regmap, csr_map->base + M10BMC_N6000_TIME_HIGH,
			   upper_32_bits(time_ms));
	if (!ret) {
		ret = regmap_write(log->m10bmc->regmap, csr_map->base + M10BMC_N6000_TIME_LOW,
				   lower_32_bits(time_ms));
	}
	if (ret)
		dev_err_once(log->dev, "Failed to update BMC timestamp: %d\n", ret);

	schedule_delayed_work(&log->dwork, log->freq_s * HZ);
}

static ssize_t time_sync_frequency_store(struct device *dev, struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct m10bmc_log *ddata = dev_get_drvdata(dev);
	unsigned int old_freq = ddata->freq_s;
	int ret;

	ret = kstrtouint(buf, 0, &ddata->freq_s);
	if (ret)
		return ret;

	if (old_freq)
		cancel_delayed_work_sync(&ddata->dwork);

	if (ddata->freq_s)
		m10bmc_log_time_sync(&ddata->dwork.work);

	return count;
}

static ssize_t time_sync_frequency_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	struct m10bmc_log *ddata = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u\n", ddata->freq_s);
}
static DEVICE_ATTR_RW(time_sync_frequency);

static struct attribute *m10bmc_log_attrs[] = {
	&dev_attr_time_sync_frequency.attr,
	NULL,
};
ATTRIBUTE_GROUPS(m10bmc_log);

static int bmc_nvmem_read(struct m10bmc_log *ddata, unsigned int addr,
			  unsigned int off, void *val, size_t count)
{
	struct intel_m10bmc *m10bmc = ddata->m10bmc;
	int ret;

	if (!m10bmc->flash_bulk_ops)
		return -ENODEV;

	ret = m10bmc->flash_bulk_ops->read(m10bmc, val, addr + off, count);
	if (ret) {
		dev_err(ddata->dev, "failed to read flash %x (%d)\n", addr, ret);
		return ret;
	}

	return 0;
}

static int bmc_event_log_nvmem_read(void *priv, unsigned int off, void *val, size_t count)
{
	struct m10bmc_log *ddata = priv;

	return bmc_nvmem_read(ddata, ddata->log_cfg->el_off, off, val, count);
}

static int fpga_image_dir_nvmem_read(void *priv, unsigned int off, void *val, size_t count)
{
	struct m10bmc_log *ddata = priv;

	return bmc_nvmem_read(ddata, ddata->log_cfg->id_off, off, val, count);
}

static int bom_info_nvmem_read(void *priv, unsigned int off, void *val, size_t count)
{
	struct m10bmc_log *ddata = priv;

	return bmc_nvmem_read(ddata, ddata->log_cfg->bi_off, off, val, count);
}

static struct nvmem_config bmc_event_log_nvmem_config = {
	.name = "bmc_event_log",
	.stride = 4,
	.word_size = 1,
	.reg_read = bmc_event_log_nvmem_read,
	.id = NVMEM_DEVID_AUTO,
};

static struct nvmem_config fpga_image_dir_nvmem_config = {
	.name = "fpga_image_directory",
	.stride = 4,
	.word_size = 1,
	.reg_read = fpga_image_dir_nvmem_read,
	.id = NVMEM_DEVID_AUTO,
};

static struct nvmem_config bom_info_nvmem_config = {
	.name = "bom_info",
	.stride = 4,
	.word_size = 1,
	.reg_read = bom_info_nvmem_read,
	.id = NVMEM_DEVID_AUTO,
};

static int m10bmc_log_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	struct m10bmc_log *ddata;
	struct nvmem_config nvconfig;

	ddata = devm_kzalloc(&pdev->dev, sizeof(*ddata), GFP_KERNEL);
	if (!ddata)
		return -ENOMEM;

	ddata->dev = &pdev->dev;
	ddata->m10bmc = dev_get_drvdata(pdev->dev.parent);
	ddata->freq_s = M10BMC_TIMESTAMP_FREQ;
	INIT_DELAYED_WORK(&ddata->dwork, m10bmc_log_time_sync);
	ddata->log_cfg = (struct m10bmc_log_cfg *)id->driver_data;
	dev_set_drvdata(&pdev->dev, ddata);

	if (ddata->log_cfg->el_size > 0) {
		m10bmc_log_time_sync(&ddata->dwork.work);

		memcpy(&nvconfig, &bmc_event_log_nvmem_config, sizeof(bmc_event_log_nvmem_config));
		nvconfig.dev = ddata->dev;
		nvconfig.priv = ddata;
		nvconfig.size = ddata->log_cfg->el_size;

		ddata->bmc_event_log_nvmem = devm_nvmem_register(ddata->dev, &nvconfig);
		if (IS_ERR(ddata->bmc_event_log_nvmem))
			return PTR_ERR(ddata->bmc_event_log_nvmem);
	}

	if (ddata->log_cfg->id_size > 0) {
		memcpy(&nvconfig, &fpga_image_dir_nvmem_config, sizeof(fpga_image_dir_nvmem_config));
		nvconfig.dev = ddata->dev;
		nvconfig.priv = ddata;
		nvconfig.size = ddata->log_cfg->id_size;

		ddata->fpga_image_dir_nvmem = devm_nvmem_register(ddata->dev, &nvconfig);
		if (IS_ERR(ddata->fpga_image_dir_nvmem))
			return PTR_ERR(ddata->fpga_image_dir_nvmem);
	}

	if (ddata->log_cfg->bi_size > 0) {
		memcpy(&nvconfig, &bom_info_nvmem_config, sizeof(bom_info_nvmem_config));
		nvconfig.dev = ddata->dev;
		nvconfig.priv = ddata;
		nvconfig.size = ddata->log_cfg->bi_size;

		ddata->bom_info_nvmem = devm_nvmem_register(ddata->dev, &nvconfig);
		if (IS_ERR(ddata->bom_info_nvmem))
			return PTR_ERR(ddata->bom_info_nvmem);
	}

	return 0;
}

static void m10bmc_log_remove(struct platform_device *pdev)
{
	struct m10bmc_log *ddata = dev_get_drvdata(&pdev->dev);

	cancel_delayed_work_sync(&ddata->dwork);
}

static const struct m10bmc_log_cfg m10bmc_log_n6000_cfg = {
	.el_size = M10BMC_N6000_ERROR_LOG_SIZE,
	.el_off = M10BMC_N6000_ERROR_LOG_ADDR,

	.id_size = M10BMC_N6000_FPGA_IMAGE_DIR_SIZE,
	.id_off = M10BMC_N6000_FPGA_IMAGE_DIR_ADDR,

	.bi_size = M10BMC_N6000_BOM_INFO_SIZE,
	.bi_off = M10BMC_N6000_BOM_INFO_ADDR,
};

static const struct m10bmc_log_cfg m10bmc_log_c6100_cfg = {
	.el_size = M10BMC_N6000_ERROR_LOG_SIZE,
	.el_off = M10BMC_C6100_ERROR_LOG_ADDR,

	.id_size = M10BMC_C6100_FPGA_IMAGE_DIR_SIZE,
	.id_off = M10BMC_C6100_FPGA_IMAGE_DIR_ADDR,
};

static const struct platform_device_id intel_m10bmc_log_ids[] = {
	{
		.name = "n6000bmc-log",
		.driver_data = (unsigned long)&m10bmc_log_n6000_cfg,
	},
	{
		.name = "c6100bmc-log",
		.driver_data = (unsigned long)&m10bmc_log_c6100_cfg,
	},
	{ }
};

static struct platform_driver intel_m10bmc_log_driver = {
	.probe = m10bmc_log_probe,
	.remove = m10bmc_log_remove,
	.driver = {
		.name = "intel-m10-bmc-log",
		.dev_groups = m10bmc_log_groups,
	},
	.id_table = intel_m10bmc_log_ids,
};
module_platform_driver(intel_m10bmc_log_driver);

MODULE_DEVICE_TABLE(platform, intel_m10bmc_log_ids);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC Log");
MODULE_LICENSE("GPL");
