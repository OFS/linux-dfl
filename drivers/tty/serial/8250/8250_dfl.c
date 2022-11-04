// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for FPGA UART
 *
 * Copyright (C) 2022 Intel Corporation, Inc.
 *
 * Authors:
 *   Ananda Ravuri <ananda.ravuri@intel.com>
 *   Matthew Gerlach <matthew.gerlach@linux.intel.com>
 */

#include <linux/dfl.h>
#include <linux/version.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bitfield.h>
#include <linux/io-64-nonatomic-lo-hi.h>

struct dfl_uart {
	void __iomem   *csr_base;
	u64             csr_addr;
	unsigned int    csr_size;
	struct device  *dev;
	u64             uart_clk;
	u64             fifo_len;
	unsigned int    fifo_size;
	unsigned int    reg_shift;
	unsigned int    line;
};

int feature_uart_walk(struct dfl_uart *dfluart, resource_size_t max)
{
	void __iomem *param_base;
	int off;
	u64 v;

	v = readq(dfluart->csr_base + DFHv1_CSR_ADDR);
	dfluart->csr_addr = FIELD_GET(DFHv1_CSR_ADDR_MASK, v);

	v = readq(dfluart->csr_base + DFHv1_CSR_SIZE_GRP);
	dfluart->csr_size = FIELD_GET(DFHv1_CSR_SIZE_GRP_SIZE, v);

	if (dfluart->csr_addr == 0 || dfluart->csr_size == 0) {
		dev_err(dfluart->dev, "FIXME bad dfh address and size\n");
		return -EINVAL;
	}

	if (!FIELD_GET(DFHv1_CSR_SIZE_GRP_HAS_PARAMS, v)) {
		dev_err(dfluart->dev, "missing required parameters\n");
		return -EINVAL;
	}

	param_base = dfluart->csr_base + DFHv1_PARAM_HDR;

	off = dfl_find_param(param_base, max, DFHv1_PARAM_ID_CLK_FRQ);
	if (off < 0) {
		dev_err(dfluart->dev, "missing CLK_FRQ param\n");
		return -EINVAL;
	}

	dfluart->uart_clk = readq(param_base + off + DFHv1_PARAM_DATA);
	dev_dbg(dfluart->dev, "UART_CLK_ID %llu Hz\n", dfluart->uart_clk);

	off = dfl_find_param(param_base, max, DFHv1_PARAM_ID_FIFO_LEN);
	if (off < 0) {
		dev_err(dfluart->dev, "missing FIFO_LEN param\n");
		return -EINVAL;
	}

	dfluart->fifo_len = readq(param_base + off + DFHv1_PARAM_DATA);
	dev_dbg(dfluart->dev, "UART_FIFO_ID fifo_len %llu\n", dfluart->fifo_len);

	off = dfl_find_param(param_base, max, DFHv1_PARAM_ID_REG_LAYOUT);
	if (off < 0) {
		dev_err(dfluart->dev, "missing REG_LAYOUT param\n");
		return -EINVAL;
	}

	v = readq(param_base + off + DFHv1_PARAM_DATA);
	dfluart->fifo_size = FIELD_GET(DFHv1_PARAM_ID_REG_WIDTH, v);
	dfluart->reg_shift = FIELD_GET(DFHv1_PARAM_ID_REG_SHIFT, v);
	dev_dbg(dfluart->dev, "UART_LAYOUT_ID width %d shift %d\n",
		dfluart->fifo_size, dfluart->reg_shift);

	return 0;
}

static int dfl_uart_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct uart_8250_port uart;
	struct dfl_uart *dfluart;
	int ret;

	memset(&uart, 0, sizeof(uart));

	dfluart = devm_kzalloc(dev, sizeof(*dfluart), GFP_KERNEL);
	if (!dfluart)
		return -ENOMEM;

	dfluart->dev = dev;

	dfluart->csr_base = devm_ioremap_resource(dev, &dfl_dev->mmio_res);
	if (IS_ERR(dfluart->csr_base)) {
		dev_err(dev, "failed to get mem resource!\n");
		return PTR_ERR(dfluart->csr_base);
	}

	ret = feature_uart_walk(dfluart, resource_size(&dfl_dev->mmio_res));

	devm_iounmap(dev, dfluart->csr_base);
	devm_release_mem_region(dev, dfl_dev->mmio_res.start, resource_size(&dfl_dev->mmio_res));

	if (ret < 0) {
		dev_err(dev, "failed to uart feature walk %d\n", ret);
		return -EINVAL;
	}

	dev_dbg(dev, "nr_irqs %d %p\n", dfl_dev->num_irqs, dfl_dev->irqs);

	if (dfl_dev->num_irqs == 1)
		uart.port.irq = dfl_dev->irqs[0];

	switch (dfluart->fifo_len) {
	case 32:
		uart.port.type = PORT_ALTR_16550_F32;
		break;

	case 64:
		uart.port.type = PORT_ALTR_16550_F64;
		break;

	case 128:
		uart.port.type = PORT_ALTR_16550_F128;
		break;

	default:
		dev_err(dev, "bad fifo_len %llu\n", dfluart->fifo_len);
		return -EINVAL;
	}

	uart.port.iotype = UPIO_MEM32;
	uart.port.mapbase = dfl_dev->mmio_res.start + dfluart->csr_addr;
	uart.port.mapsize = dfluart->csr_size;
	uart.port.regshift = dfluart->reg_shift;
	uart.port.uartclk = dfluart->uart_clk;
	uart.port.flags |= UPF_IOREMAP;

	/* register the port */
	ret = serial8250_register_8250_port(&uart);
	if (ret < 0) {
		dev_err(dev, "unable to register 8250 port %d.\n", ret);
		return -EINVAL;
	}
	dev_info(dev, "serial8250_register_8250_port %d\n", ret);
	dfluart->line = ret;
	dev_set_drvdata(dev, dfluart);

	return 0;
}

static void dfl_uart_remove(struct dfl_device *dfl_dev)
{
	struct dfl_uart *dfluart = dev_get_drvdata(&dfl_dev->dev);

	if (dfluart->line > 0)
		serial8250_unregister_port(dfluart->line);
}

#define FME_FEATURE_ID_UART 0x24

#define FME_GUID_UART \
	GUID_INIT(0x9e6641a6, 0xca26, 0xcc04, 0xe1, 0xdf, \
			0x0d, 0x4a, 0xce, 0x8e, 0x48, 0x6c)

static const struct dfl_device_id dfl_uart_ids[] = {
	{ FME_ID, FME_FEATURE_ID_UART, .guid = FME_GUID_UART },
	{ }
};

static struct dfl_driver dfl_uart_driver = {
	.drv = {
		.name = "dfl-uart",
	},
	.id_table = dfl_uart_ids,
	.probe = dfl_uart_probe,
	.remove = dfl_uart_remove,
};

module_dfl_driver(dfl_uart_driver);

MODULE_DEVICE_TABLE(dfl, dfl_uart_ids);
MODULE_DESCRIPTION("DFL Intel UART driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
