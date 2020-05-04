This directory contains linux kernel configuration fragments related to
the Device Feature List (DFL) driver collection. By design the DFL driver
collection is extendable, and it is anticipated that new drivers will be added
to the collection.

The fragments are intended to be appended to a base kernel configuration.
For example the following commands would configure the kernel source to
support the Intel n3000 and d5005 PCIe cards:

	# cd kernel_source_directory
	# cp /boot/config-`uname -r` .config
	# cat configs/n3000_d5005_defconfig >> .config
	# make olddefconfig

n3000_d5005_defconfig
	Default configuration for Intel n3000 and d5005 PCIe cards.
