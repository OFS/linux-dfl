.. SPDX-License-Identifier: GPL-2.0+

=======================================================================
DFL device driver for Ether Group private feature on Intel(R) PAC N3000
=======================================================================

This is the driver for Ether Group private feature on Intel(R)
PAC (Programmable Acceleration Card) N3000.

The Intel(R) PAC N3000 is a FPGA based SmartNIC platform for multi-workload
networking application acceleration. A simple diagram below to for the board:

                     +----------------------------------------+
                     |                  FPGA                  |
+----+   +-------+   +-----------+  +----------+  +-----------+   +----------+
|QSFP|---|retimer|---|Line Side  |--|User logic|--|Host Side  |---|XL710     |
+----+   +-------+   |Ether Group|  |          |  |Ether Group|   |Ethernet  |
                     |(PHY + MAC)|  |wiring &  |  |(MAC + PHY)|   |Controller|
                     +-----------+  |offloading|  +-----------+   +----------+
                     |              +----------+              |
                     |                                        |
                     +----------------------------------------+

The FPGA is composed of FPGA Interface Module (FIM) and Accelerated Function
Unit (AFU). The FIM implements the basic functionalities for FPGA access,
management and reprograming, while the AFU is the FPGA reprogramable region for
users.

The Line Side & Host Side Ether Groups are soft IP blocks embedded in FIM. They
are internally wire connected to AFU and communicate with AFU with MAC packets.
The user logic is developed by the FPGA users and re-programmed to AFU,
providing the user defined wire connections between line side & host side data
interfaces, as well as the MAC layer offloading.

There are 2 types of interfaces for the Ether Groups:

1. The data interfaces connects the Ether Groups and the AFU, host has no
ability to control the data stream . So the FPGA is like a pipe between the
host ethernet controller and the retimer chip.

2. The management interfaces connects the Ether Groups to the host, so host
could access the Ether Group registers for configuration and statistics
reading.

The Intel(R) PAC N3000 could be programmed to various configurations (with
different link numbers and speeds, e.g. 8x10G, 4x25G ...). It is done by
programing different variants of the Ether Group IP blocks, and doing
corresponding configuration to the retimer chips.

The DFL Ether Group driver registers netdev for each line side link. Users
could use standard commands (ethtool, ip, ifconfig) for configuration and
link state/statistics reading. For host side links, they are always connected
to the host ethernet controller, so they should always have same features as
the host ethernet controller. There is no need to register netdevs for them.
The driver just enables these links on probe.

The retimer chips are managed by onboard BMC (Board Management Controller)
firmware, host driver is not capable to access them directly. So it is mostly
like an external fixed PHY. However the link states detected by the retimer
chips can not be propagated to the Ether Groups for hardware limitation, in
order to manage the link state, a PHY driver (intel-m10-bmc-retimer) is
introduced to query the BMC for the retimer's link state. The Ether Group
driver would connect to the PHY devices and get the link states. The
intel-m10-bmc-retimer driver creates a peseudo MDIO bus for each board, so
that the Ether Group driver could find the PHY devices by their peseudo PHY
addresses.


2. Features supported
=====================

Data Path
---------
Since the driver can't control the data stream, the Ether Group driver
doesn't implement the valid tx/rx functions. Any transmit attempt on these
links from host will be dropped, and no data could be received to host from
these links. Users should operate on the netdev of host ethernet controller
for networking data traffic.


Speed/Duplex
------------
The Ether Group doesn't support auto-negotiation. The link speed is fixed to
10G, 25G or 40G full duplex according to which Ether Group IP is programmed.

Statistics
----------
The Ether Group IP has the statistics counters for ethernet traffic and errors.
The user can obtain these MAC-level statistics using "ethtool -S" option.

MTU
---
The Ether Group IP is capable of detecting oversized packets. It will not drop
the packet but pass it up and increment the tx/rx oversize counters. The MTU
could be changed via ip or ifconfig commands.

Flow Control
------------
Ethernet Flow Control (IEEE 802.3x) can be configured with ethtool to enable
transmitting pause frames. Receiving pause request from outside to Ether Group
MAC is not supported. The flow control auto-negotiation is not supported. The
user can enable or disable Tx Flow Control using "ethtool -A eth? tx <on|off>"
