.. SPDX-License-Identifier: GPL-2.0

=================================
N3000 Nios Private Feature Driver
=================================

The N3000 Nios driver supports for the Nios handshake private feature on Intel
PAC (Programmable Acceleration Card) N3000.

The Nios is the embedded processor in the FPGA, it will configure the 2 onboard
ethernet retimers on power up. This private feature provides a handshake
interface to FPGA Nios firmware, which receives the ethernet retimer
configuration command from host and does the configuration via an internal SPI
master (spi-altera). When Nios finishes the configuration, host takes over the
ownership of the SPI master to control an Intel MAX10 BMC (Board Management
Controller) Chip on the SPI bus.

So the driver does 2 major tasks on probe, uses the Nios firmware to configure
the ethernet retimer, and then creates a spi master platform device with the
MAX10 device info in spi_board_info.


Configuring the ethernet retimer
================================

The Intel PAC N3000 is a FPGA based SmartNIC platform which could be programmed
to various configurations (with different link numbers and speeds, e.g. 8x10G,
4x25G ...). And the retimer chips should also be configured correspondingly by
Nios firmware. There are 2 retimer chips on the board, each of them supports 4
links. For example, in 8x10G configuration, the 2 retimer chips are both set to
4x10G mode, while in 4x25G configuration, retimer A is set to 4x25G and retimer
B is in reset. For now, the Nios firmware only supports 10G and 25G mode
setting for the retimer chips.

For all 25G links, their FEC (Forward Error Correction) mode could be further
configured by Nios firmware for user's requirement. For 10G links, they don't
have the FEC mode at all, the firmware ignores the FEC mode setting for them.
The FEC setting is not supported if the firmware version major < 3.

The retimer configuration can only be done once after the board powers up, the
Nios firmware will not accept second configuration afterward. So it is not
proper for the driver to create a RW sysfs node for the FEC mode. A better way
is that the driver accepts a module parameter for the FEC mode, and does the
retimer configuration on driver probe, it also creates a RO sysfs node for the
FEC mode query.

Module Parameters
=================

The N3000 Nios driver supports the following module parameters:

* fec_mode: string
  Require the Nios firmware to set the FEC mode for all 25G links of the
  ethernet retimers. The Nios firmware configures all these links with the same
  FEC mode. The possible values of fec_mode could be:

  - "rs": Reed Solomon FEC (default)
  - "kr": Fire Code FEC
  - "no": No FEC

  Since the firmware doesn't accept second configuration, The FEC mode will not
  be changed if the module is reloaded with a different parameter value.

  The parameter has no effect for 10G links. It has no effect to all the links
  if firmware version major < 3.


Sysfs Attributes
================

The driver creates some attributes in sysfs for users to query the retimer
info. Please see Documentation/ABI/testing/sysfs-bus-dfl-devices-n3000-nios for
more details.
