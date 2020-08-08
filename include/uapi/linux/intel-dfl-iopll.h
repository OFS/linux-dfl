/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Header File for the IOPLL driver for the Intel PAC
 *
 * Copyright 2018-2020 Intel Corporation, Inc.
 */

#ifndef _UAPI_INTEL_DFL_IOPLL_H
#define _UAPI_INTEL_DFL_IOPLL_H

/*
 * IOPLL Configuration support.
 */
#define  IOPLL_MAX_FREQ         600
#define  IOPLL_MIN_FREQ         1

struct pll_config {
	unsigned int pll_freq_khz;
	unsigned int pll_m;
	unsigned int pll_n;
	unsigned int pll_c1;
	unsigned int pll_c0;
	unsigned int pll_lf;
	unsigned int pll_cp;
	unsigned int pll_rc;
};

#endif /* _UAPI_INTEL_DFL_IOPLL_H */
