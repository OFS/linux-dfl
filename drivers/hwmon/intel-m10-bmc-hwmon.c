// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Max10 BMC HWMON Driver
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/mfd/intel-m10-bmc.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>

enum m10bmc_channel_type {
	M10BMC_CHT_TEMP,
	M10BMC_CHT_IN,
	M10BMC_CHT_CURR,
	M10BMC_CHT_POWER,
	M10BMC_CHT_MAX,
};

struct m10bmc_sdata {
	unsigned int type;

	unsigned int reg_input;
	unsigned int reg_max;
	unsigned int reg_crit;
	unsigned int reg_hyst;
	unsigned int reg_min;
	unsigned int multiplier;

	const char *label;
};

struct m10bmc_sdata pacn3000_sensor_tbl[] = {
	{ M10BMC_CHT_TEMP, 0x100, 0x104, 0x108, 0x10c, 0x0, 500,
	 "Board Temperature" },
	{ M10BMC_CHT_TEMP, 0x110, 0x114, 0x118, 0x0, 0x0, 500,
	 "FPGA Die Temperature" },
	{ M10BMC_CHT_TEMP, 0x11c, 0x120, 0x124, 0x0, 0x0, 500,
	 "QSFP0 Temperature" },
	{ M10BMC_CHT_IN, 0x128, 0x0, 0x0, 0x0, 0x0, 1,
	 "QSFP0 Supply Voltage" },
	{ M10BMC_CHT_TEMP, 0x12c, 0x130, 0x134, 0x0, 0x0, 500,
	 "QSFP1 Temperature" },
	{ M10BMC_CHT_IN, 0x138, 0x0, 0x0, 0x0, 0x0, 1,
	 "QSFP1 Supply Voltage" },
	{ M10BMC_CHT_IN, 0x13c, 0x0, 0x0, 0x0, 0x0, 1,
	 "FPGA Core Voltage" },
	{ M10BMC_CHT_CURR, 0x140, 0x0, 0x0, 0x0, 0x0, 1,
	 "FPGA Core Current" },
	{ M10BMC_CHT_IN, 0x144, 0x0, 0x0, 0x0, 0x0, 1,
	 "12V Backplane Voltage" },
	{ M10BMC_CHT_CURR, 0x148, 0x0, 0x0, 0x0, 0x0, 1,
	 "12V Backplane Current" },
	{ M10BMC_CHT_IN, 0x14c, 0x0, 0x0, 0x0, 0x0, 1,
	 "1.2V Voltage" },
	{M10BMC_CHT_IN, 0x150, 0x0, 0x0, 0x0, 0x0, 1,
	 "12V AUX Voltage" },
	{ M10BMC_CHT_CURR, 0x154, 0x0, 0x0, 0x0, 0x0, 1,
	 "12V AUX Current" },
	{ M10BMC_CHT_IN, 0x158, 0x0, 0x0, 0x0, 0x0, 1,
	 "1.8V Voltage" },
	{ M10BMC_CHT_IN, 0x15c, 0x0, 0x0, 0x0, 0x0, 1,
	 "3.3V Voltage" },
	{ M10BMC_CHT_POWER, 0x160, 0x0, 0x0, 0x0, 0x0, 1000,
	 "Board Power" },
	{ M10BMC_CHT_TEMP, 0x168, 0x0, 0x0, 0x0, 0x0, 500,
	 "PKVL1 Temperature" },
	{ M10BMC_CHT_TEMP, 0x16c, 0x0, 0x0, 0x0, 0x0, 500,
	 "PKVL1 SerDes Temperature" },
	{ M10BMC_CHT_TEMP, 0x170, 0x0, 0x0, 0x0, 0x0, 500,
	 "PKVL2 Temperature" },
	{ M10BMC_CHT_TEMP, 0x174, 0x0, 0x0, 0x0, 0x0, 500,
	 "PKVL2 SerDes Temperature" },
	{ M10BMC_CHT_MAX } /* sentinel */
};

struct m10bmc_sdata pacd5005_sensor_tbl[] = {
	{ M10BMC_CHT_TEMP, 0x100, 0x104, 0x108, 0x10c, 0x0, 500,
	 "Board Inlet Air Temperature" },
	{ M10BMC_CHT_TEMP, 0x110, 0x114, 0x118, 0x0, 0x0, 500,
	 "FPGA Core Temperature" },
	{ M10BMC_CHT_TEMP, 0x11c, 0x120, 0x124, 0x128, 0x0, 500,
	 "Board Exhaust Air Temperature" },
	{ M10BMC_CHT_TEMP, 0x12c, 0x130, 0x134, 0x0, 0x0, 500,
	 "FPGA Transceiver Temperature" },
	{ M10BMC_CHT_TEMP, 0x138, 0x13c, 0x140, 0x144, 0x0, 500,
	 "RDIMM0 Temperature" },
	{ M10BMC_CHT_TEMP, 0x148, 0x14c, 0x150, 0x154, 0x0, 500,
	 "RDIMM1 Temperature" },
	{ M10BMC_CHT_TEMP, 0x158, 0x15c, 0x160, 0x164, 0x0, 500,
	 "RDIMM2 Temperature" },
	{ M10BMC_CHT_TEMP, 0x168, 0x16c, 0x170, 0x174, 0x0, 500,
	 "RDIMM3 Temperature" },
	{ M10BMC_CHT_TEMP, 0x178, 0x17c, 0x180, 0x0, 0x0, 500,
	 "QSFP0 Temperature" },
	{ M10BMC_CHT_IN, 0x184, 0x0, 0x0, 0x0, 0x0, 1,
	  "QSFP0 Supply Voltage" },
	{ M10BMC_CHT_TEMP, 0x188, 0x18c, 0x190, 0x0, 0x0, 500,
	 "QSFP1 Temperature" },
	{ M10BMC_CHT_IN, 0x194, 0x0, 0x0, 0x0, 0x0, 1,
	  "QSFP1 Supply Voltage" },
	{ M10BMC_CHT_IN, 0x198, 0x0, 0x0, 0x0, 0x0, 1,
	  "FPGA Core Voltage" },
	{ M10BMC_CHT_CURR, 0x19c, 0x0, 0x0, 0x0, 0x0, 1,
	  "FPGA Core Current" },
	{ M10BMC_CHT_TEMP, 0x1a0, 0x1a4, 0x1a8, 0x0, 0x0, 500,
	 "3.3v Temperature" },
	{ M10BMC_CHT_IN, 0x1ac, 0x1b0, 0x1b4, 0x0, 0x0, 1,
	  "3.3v Voltage" },
	{ M10BMC_CHT_CURR, 0x1b8, 0x0, 0x0, 0x0, 0x0, 1,
	  "3.3v Current" },
	{ M10BMC_CHT_TEMP, 0x1bc, 0x1c0, 0x1c4, 0x0, 0x0, 500,
	 "VCCERAM Temperature" },
	{ M10BMC_CHT_IN, 0x1c8, 0x1cc, 0x1d0, 0x0, 0x0, 1,
	  "VCCERAM Voltage" },
	{ M10BMC_CHT_CURR, 0x1d4, 0x0, 0x0, 0x0, 0x0, 1,
	  "VCCERAM Current" },
	{ M10BMC_CHT_TEMP, 0x1d8, 0x1dc, 0x1e0, 0x0, 0x0, 500,
	 "VCCR Temperature" },
	{ M10BMC_CHT_IN, 0x1e4, 0x1e8, 0x1ec, 0x0, 0x0, 1,
	  "VCCR Voltage" },
	{ M10BMC_CHT_CURR, 0x1f0, 0x0, 0x0, 0x0, 0x0, 1,
	  "VCCR Current" },
	{ M10BMC_CHT_TEMP, 0x1f4, 0x1f8, 0x1fc, 0x0, 0x0, 500,
	 "VCCT Temperature" },
	{ M10BMC_CHT_IN, 0x200, 0x204, 0x208, 0x0, 0x0, 1,
	  "VCCT Voltage" },
	{ M10BMC_CHT_CURR, 0x20c, 0x0, 0x0, 0x0, 0x0, 1,
	  "VCCT Current" },
	{ M10BMC_CHT_TEMP, 0x210, 0x214, 0x218, 0x0, 0x0, 500,
	 "1.8v Temperature" },
	{ M10BMC_CHT_IN, 0x21c, 0x220, 0x224, 0x0, 0x0, 1,
	  "1.8v Voltage" },
	{ M10BMC_CHT_CURR, 0x228, 0x0, 0x0, 0x0, 0x0, 1,
	  "1.8v Current" },
	{ M10BMC_CHT_TEMP, 0x22c, 0x230, 0x234, 0x0, 0x0, 500,
	 "12v Backplane Temperature" },
	{ M10BMC_CHT_IN, 0x238, 0x0, 0x0, 0x0, 0x23c, 1,
	  "12v Backplane Voltage" },
	{ M10BMC_CHT_CURR, 0x240, 0x244, 0x0, 0x0, 0x0, 1,
	  "12v Backplane Current" },
	{ M10BMC_CHT_TEMP, 0x248, 0x24c, 0x250, 0x0, 0x0, 500,
	 "12v AUX Temperature" },
	{ M10BMC_CHT_IN, 0x254, 0x0, 0x0, 0x0, 0x258, 1,
	  "12v AUX Voltage" },
	{ M10BMC_CHT_CURR, 0x25c, 0x260, 0x0, 0x0, 0x0, 1,
	  "12v AUX Current" },
	{ M10BMC_CHT_MAX } /* sentinel */
};

struct m10bmc_ch_group {
	struct m10bmc_sdata **data_list;
	u32 *config;
	struct hwmon_channel_info info;
};

struct m10bmc_hwmon {
	struct device *dev;
	struct m10bmc_ch_group chgs[M10BMC_CHT_MAX];
	/* This is a NULL terminated array required by HWMON interface */
	const struct hwmon_channel_info *info[M10BMC_CHT_MAX + 1];
	struct hwmon_chip_info chip;
	char *hw_name;
	struct intel_m10bmc *m10bmc;
	struct m10bmc_sdata *data_tbl;
};

static enum m10bmc_channel_type
htype_to_ctype(enum hwmon_sensor_types htype)
{
	switch (htype) {
	case hwmon_temp:
		return M10BMC_CHT_TEMP;
	case hwmon_in:
		return M10BMC_CHT_IN;
	case hwmon_curr:
		return M10BMC_CHT_CURR;
	case hwmon_power:
		return M10BMC_CHT_POWER;
	default:
		return M10BMC_CHT_MAX;
	}
}

static enum hwmon_sensor_types
ctype_to_htype(enum m10bmc_channel_type ctype)
{
	switch (ctype) {
	case M10BMC_CHT_TEMP:
		return hwmon_temp;
	case M10BMC_CHT_IN:
		return hwmon_in;
	case M10BMC_CHT_CURR:
		return hwmon_curr;
	case M10BMC_CHT_POWER:
		return hwmon_power;
	default:
		return hwmon_max;
	}
}

static umode_t
m10bmc_hwmon_is_visible(const void *data, enum hwmon_sensor_types type,
			u32 attr, int channel)
{
	return 0444;
}

static struct m10bmc_sdata *
find_sensor_data(struct m10bmc_hwmon *hw, enum hwmon_sensor_types htype,
		 int channel)
{
	enum m10bmc_channel_type ctype = htype_to_ctype(htype);

	if (ctype >= M10BMC_CHT_MAX)
		return NULL;

	return hw->chgs[ctype].data_list[channel];
}

static int do_sensor_read(struct m10bmc_hwmon *hw, struct m10bmc_sdata *data,
			  unsigned int regoff, long *val)
{
	unsigned int regval;
	int ret;

	ret = m10bmc_sys_read(hw->m10bmc, regoff, &regval);
	if (ret)
		return ret;

	/*
	 * BMC Firmware will return 0xdeadbeef if sensor value is invalid at
	 * that time. This usually happens on sensor channels which connect to
	 * external pluggable modules, e.g. QSFP Temperature and Voltage. When
	 * QSFP is unplugged from cage, driver will get 0xdeadbeef from their
	 * registers.
	 */
	if (regval == 0xdeadbeef)
		return -EBUSY;

	*val = regval * data->multiplier;

	return 0;
}

static int m10bmc_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			     u32 attr, int channel, long *val)
{
	struct m10bmc_hwmon *hw = dev_get_drvdata(dev);
	unsigned int reg, reg_hyst = 0;
	struct m10bmc_sdata *data;
	long hyst, value;
	int ret;

	data = find_sensor_data(hw, type, channel);
	if (!data)
		return -EOPNOTSUPP;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
			reg = data->reg_input;
			break;
		case hwmon_temp_max_hyst:
			reg_hyst = data->reg_hyst;
			fallthrough;
		case hwmon_temp_max:
			reg = data->reg_max;
			break;
		case hwmon_temp_crit_hyst:
			reg_hyst = data->reg_hyst;
			fallthrough;
		case hwmon_temp_crit:
			reg = data->reg_crit;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case hwmon_in:
		switch (attr) {
		case hwmon_in_input:
			reg = data->reg_input;
			break;
		case hwmon_in_max:
			reg = data->reg_max;
			break;
		case hwmon_in_crit:
			reg = data->reg_crit;
			break;
		case hwmon_in_min:
			reg = data->reg_min;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case hwmon_curr:
		switch (attr) {
		case hwmon_curr_input:
			reg = data->reg_input;
			break;
		case hwmon_curr_max:
			reg = data->reg_max;
			break;
		case hwmon_curr_crit:
			reg = data->reg_crit;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case hwmon_power:
		switch (attr) {
		case hwmon_power_input:
			reg = data->reg_input;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = do_sensor_read(hw, data, reg, &value);
	if (ret)
		return ret;

	if (reg_hyst) {
		ret = do_sensor_read(hw, data, reg_hyst, &hyst);
		if (ret)
			return ret;

		value -= hyst;
	}

	*val = value;

	return ret;
}

static int m10bmc_hwmon_read_string(struct device *dev,
				    enum hwmon_sensor_types type,
				    u32 attr, int channel, const char **str)
{
	struct m10bmc_hwmon *hw = dev_get_drvdata(dev);
	struct m10bmc_sdata *data;

	data = find_sensor_data(hw, type, channel);
	if (!data)
		return -EOPNOTSUPP;

	*str = data->label;

	return 0;
}

static const struct hwmon_ops m10bmc_hwmon_ops = {
	.is_visible = m10bmc_hwmon_is_visible,
	.read = m10bmc_hwmon_read,
	.read_string = m10bmc_hwmon_read_string,
};

int m10bmc_malloc_channels(struct device *dev, struct m10bmc_ch_group *chg,
			   int num_ch)
{
	chg->config = devm_kcalloc(dev, num_ch + 1,
				   sizeof(*chg->config), GFP_KERNEL);
	if (!chg->config)
		return -ENOMEM;

	chg->data_list = devm_kcalloc(dev, num_ch, sizeof(*chg->data_list),
				      GFP_KERNEL);
	if (!chg->data_list)
		return -ENOMEM;

	chg->info.config = chg->config;

	return 0;
}

void m10bmc_fill_temp_channel(struct m10bmc_hwmon *hwmon, int ch_idx,
			      struct m10bmc_sdata *data)
{
	struct m10bmc_ch_group *chg = &hwmon->chgs[M10BMC_CHT_TEMP];

	if (data->reg_input)
		chg->config[ch_idx] |= HWMON_T_INPUT;

	if (data->reg_max) {
		chg->config[ch_idx] |= HWMON_T_MAX;
		if (data->reg_hyst)
			chg->config[ch_idx] |= HWMON_T_MAX_HYST;
	}

	if (data->reg_crit) {
		chg->config[ch_idx] |= HWMON_T_CRIT;
		if (data->reg_hyst)
			chg->config[ch_idx] |= HWMON_T_CRIT_HYST;
	}

	if (data->label)
		chg->config[ch_idx] |= HWMON_T_LABEL;

	chg->data_list[ch_idx] = data;
}

void m10bmc_fill_in_channel(struct m10bmc_hwmon *hwmon, int ch_idx,
			    struct m10bmc_sdata *data)
{
	struct m10bmc_ch_group *chg = &hwmon->chgs[M10BMC_CHT_IN];

	if (data->reg_input)
		chg->config[ch_idx] |= HWMON_I_INPUT;

	if (data->reg_max)
		chg->config[ch_idx] |= HWMON_I_MAX;

	if (data->reg_crit)
		chg->config[ch_idx] |= HWMON_I_CRIT;

	if (data->reg_min)
		chg->config[ch_idx] |= HWMON_I_MIN;

	if (data->label)
		chg->config[ch_idx] |= HWMON_I_LABEL;

	chg->data_list[ch_idx] = data;
}

void m10bmc_fill_curr_channel(struct m10bmc_hwmon *hwmon, int ch_idx,
			      struct m10bmc_sdata *data)
{
	struct m10bmc_ch_group *chg = &hwmon->chgs[M10BMC_CHT_CURR];

	if (data->reg_input)
		chg->config[ch_idx] |= HWMON_C_INPUT;

	if (data->reg_max)
		chg->config[ch_idx] |= HWMON_C_MAX;

	if (data->reg_crit)
		chg->config[ch_idx] |= HWMON_C_CRIT;

	if (data->label)
		chg->config[ch_idx] |= HWMON_C_LABEL;

	chg->data_list[ch_idx] = data;
}

void m10bmc_fill_power_channel(struct m10bmc_hwmon *hwmon, int ch_idx,
			       struct m10bmc_sdata *data)
{
	struct m10bmc_ch_group *chg = &hwmon->chgs[M10BMC_CHT_POWER];

	if (data->reg_input)
		chg->config[ch_idx] |= HWMON_P_INPUT;

	if (data->label)
		chg->config[ch_idx] |= HWMON_P_LABEL;

	chg->data_list[ch_idx] = data;
}

static int m10bmc_hwmon_init(struct device *dev, struct intel_m10bmc *m10bmc,
			     const char *dev_name,
			     struct m10bmc_sdata *data_tbl)
{
	int num_ch[M10BMC_CHT_MAX] = { 0 }, ret, i, j;
	struct m10bmc_sdata *data = data_tbl;
	struct device *hwmon_dev;
	struct m10bmc_hwmon *hw;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -EINVAL;

	hw->dev = dev;
	hw->m10bmc = m10bmc;
	hw->data_tbl = data_tbl;

	while (data->type != M10BMC_CHT_MAX) {
		if (data->type > M10BMC_CHT_MAX)
			return -EINVAL;

		++num_ch[data->type];
		++data;
	}

	for (i = 0; i < M10BMC_CHT_MAX; i++) {
		if (!num_ch[i])
			continue;

		ret = m10bmc_malloc_channels(dev, &hw->chgs[i],
					     num_ch[i]);
		if (ret)
			return ret;

		hw->chgs[i].info.type = ctype_to_htype(i);
	}

	data = data_tbl;
	memset(&num_ch, 0, sizeof(num_ch));
	while (data->type != M10BMC_CHT_MAX) {
		switch (data->type) {
		case M10BMC_CHT_TEMP:
			m10bmc_fill_temp_channel(hw, num_ch[data->type],
						 data);
			break;
		case M10BMC_CHT_IN:
			m10bmc_fill_in_channel(hw, num_ch[data->type],
					       data);
			break;
		case M10BMC_CHT_CURR:
			m10bmc_fill_curr_channel(hw, num_ch[data->type],
						 data);
			break;
		case M10BMC_CHT_POWER:
			m10bmc_fill_power_channel(hw, num_ch[data->type],
						  data);
			break;
		}

		++num_ch[data->type];
		++data;
	}

	for (i = 0, j = 0; i < M10BMC_CHT_MAX; i++) {
		if (num_ch[i])
			hw->info[j++] = &hw->chgs[i].info;
	}

	hw->chip.info = hw->info;
	hw->chip.ops = &m10bmc_hwmon_ops;

	hw->hw_name = devm_kstrdup(dev, dev_name, GFP_KERNEL);
	if (!hw->hw_name)
		return -ENOMEM;

	for (i = 0; hw->hw_name[i]; i++)
		if (hwmon_is_bad_char(hw->hw_name[i]))
			hw->hw_name[i] = '_';

	hwmon_dev = devm_hwmon_device_register_with_info(dev, hw->hw_name,
							 hw, &hw->chip, NULL);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	return 0;
}

static int m10bmc_hwmon_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	struct intel_m10bmc *m10bmc = dev_get_drvdata(pdev->dev.parent);

	return m10bmc_hwmon_init(&pdev->dev, m10bmc, id->name,
				 (struct m10bmc_sdata *)id->driver_data);
}

static const struct platform_device_id intel_m10bmc_hwmon_ids[] = {
	{
		.name = N3000BMC_HWMON_DEV_NAME,
		.driver_data = (unsigned long)&pacn3000_sensor_tbl,
	},
	{
		.name = d5005BMC_HWMON_DEV_NAME,
		.driver_data = (unsigned long)&pacd5005_sensor_tbl,
	},
	{ }
};

static struct platform_driver intel_m10bmc_hwmon_driver = {
	.probe = m10bmc_hwmon_probe,
	.driver = {
		.name = "intel-m10bmc-hwmon",
	},
	.id_table = intel_m10bmc_hwmon_ids,
};
module_platform_driver(intel_m10bmc_hwmon_driver);

MODULE_DEVICE_TABLE(platform, intel_m10bmc_hwmon_ids);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel MAX10 BMC hardware monitor");
MODULE_LICENSE("GPL");
