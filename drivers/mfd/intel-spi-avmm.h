/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver Header File for Intel SPI Slave to AVMM Bus Bridge
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */

#ifndef __INTEL_SPI_AVMM_H
#define __INTEL_SPI_AVMM_H

#include <linux/spi/spi.h>
#include <linux/regmap.h>

struct regmap *__devm_regmap_init_spi_avmm(struct spi_device *spi,
					   const struct regmap_config *config,
					   struct lock_class_key *lock_key,
					   const char *lock_name);

/**
 * devm_regmap_init_spi_avmm() - Initialize register map for Intel SPI Slave
 * to AVMM Bus Bridge
 *
 * @spi: Device that will be interacted with
 * @config: Configuration for register map
 *
 * The return value will be an ERR_PTR() on error or a valid pointer
 * to a struct regmap.  The map will be automatically freed by the
 * device management code.
 */
#define devm_regmap_init_spi_avmm(spi, config)				\
	__regmap_lockdep_wrapper(__devm_regmap_init_spi_avmm, #config,	\
				 spi, config)

#endif /* __INTEL_SPI_AVMM_H */
