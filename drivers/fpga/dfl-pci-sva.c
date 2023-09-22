// SPDX-License-Identifier: GPL-2.0-only
/*
 * Manage PASID and IOMMU binding for FPGA ports supporting shared
 * virtual addressing.
 *
 * Copyright (C) 2023 Intel Corporation, Inc.
 *
 * Authors:
 *   Michael Adler <michael.adler@intel.com>
 */

/*
 * Expose a device interface for binding a PASID to FPGA PCIe ports.
 * PCIe devices with a DFL device ID are tracked independent of their
 * current driver, making it possible to configure IOMMU SVA with
 * either dfl-pci or vfio-pci drivers. The module uses bus notifier
 * hooks in order to catch device removal when vfio-pci is bound.
 *
 * Device files named /dev/dfl-pci-sva/<pci address> are managed
 * in this module (e.g. /dev/dfl-pci-sva/0000:ab:00.3). The
 * DFL_PCI_SVA_BIND_DEV ioctl ensures a PASID is allocated, binds
 * it to the device and returns the PASID. The PASID remains bound
 * until the file is closed or DFL_PCI_SVA_UNBIND_DEV.
 */

#include <linux/fpga-dfl.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/types.h>

#include "dfl.h"

/* Device IDs of DFL-managed functions */
#define PCIE_DEVICE_ID_INTEL_DFL       0xbcce
#define PCIE_DEVICE_ID_INTEL_DFL_VF    0xbccf

static struct notifier_block sva_nb;

static DEFINE_MUTEX(dfl_dev_list_mutex);
static LIST_HEAD(dfl_dev_list);

struct dfl_sva_handle {
	struct iommu_sva *sva_handle;	  /* Handle for process SVA binding with PASID */
	struct list_head sva_next;
};

struct dfl_sva_dev {
	struct pci_dev *pdev;		  /* PCIe device to bind */
	struct miscdevice mdev;		  /* /dev/dfl-pci-sva/<addr> device */
	char mdev_name[64];		  /* dfl-pci-sva!<addr> */
	struct file_operations mdev_fops; /* dfl-pci-sva file ops */
	struct list_head sva_next;	  /* List of all SVA bindings, one per file descriptor */
	struct list_head pdev_next;	  /* List of all managed devices */
	struct mutex mutex;
};

/*
 * Enable shared virtual addressing IOMMU support if the host and FPGA
 * are configured to support it. PASID, ATS and PRS must all be enabled
 * on the FPGA or the feature can not be enabled.
 *
 * If the function returns false, SVA is not available and the
 * dfl-pci-sva device will not be created.
 */
static int enable_iommu_sva_feature(struct pci_dev *pdev)
{
	int ret;

	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
	if (ret)
		return ret;

	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
		return ret;
	}

	pci_info(pdev, "Enabled IOPF and SVA features\n");
	return 0;
}

static void disable_iommu_sva_feature(struct pci_dev *pdev)
{
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
	pci_info(pdev, "Disabled IOPF and SVA features\n");
}

static int dfl_pci_sva_open(struct inode *inode, struct file *file)
{
	struct dfl_sva_dev *dev = container_of(file->f_op, struct dfl_sva_dev, mdev_fops);
	struct pci_dev *pdev;
	struct dfl_sva_handle *sva;
	int ret = 0;

	mutex_lock(&dev->mutex);
	pdev = dev->pdev;

	if (!pdev) {
		ret = -EBUSY;
		goto out_unlock;
	}

	sva = kzalloc(sizeof(struct dfl_sva_handle), GFP_KERNEL);
	if (!sva) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	list_add(&sva->sva_next, &dev->sva_next);
	file->private_data = sva;

	pci_dbg(pdev, "%s: pid %d\n", __func__, task_pid_nr(current));

out_unlock:
	mutex_unlock(&dev->mutex);
	return ret;
}

static int dfl_pci_sva_release(struct inode *inode, struct file *file)
{
	struct dfl_sva_dev *dev = container_of(file->f_op, struct dfl_sva_dev, mdev_fops);
	struct dfl_sva_handle *sva = file->private_data;

	mutex_lock(&dev->mutex);

	if (dev->pdev) {
		pci_info(dev->pdev, "%s: pid %d, release sva_handle %p\n", __func__,
			 task_pid_nr(current), sva->sva_handle);
	}

	/* Drop the IOMMU binding and release the sva_handle */
	if (sva->sva_handle)
		iommu_sva_unbind_device(sva->sva_handle);
	list_del(&sva->sva_next);
	kfree(sva);

	if (!dev->pdev && list_empty(&dev->sva_next)) {
		/*
		 * The device was deleted while the sva file handle was open. It has already
		 * been removed from the device dfl_dev_list but the memory needs to be
		 * released. dev->mutex can be ignored since it is in the memory being freed.
		 */
		kfree(dev);
		pr_debug("%s: released device handle, pid %d\n", __func__, task_pid_nr(current));
		return 0;
	}

	mutex_unlock(&dev->mutex);
	return 0;
}

static long ioctl_sva_bind_dev(struct dfl_sva_dev *dev, struct iommu_sva **sva_handle_p)
{
	struct iommu_sva *handle;

	/* Was the device deleted while file handle is open? */
	if (!dev->pdev)
		return -ENODEV;

	if (!current->mm)
		return -EINVAL;

	if ((handle = *sva_handle_p))
		return iommu_sva_get_pasid(handle);

	handle = iommu_sva_bind_device(&dev->pdev->dev, current->mm);
	if (!handle)
		return -ENODEV;
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	pci_info(dev->pdev, "%s: pid %d, bind sva_handle %p, pasid = %d\n",
		 __func__, task_pid_nr(current),
		 handle, iommu_sva_get_pasid(handle));

	*sva_handle_p = handle;
	return iommu_sva_get_pasid(handle);
}

static long ioctl_sva_unbind_dev(struct dfl_sva_dev *dev, struct iommu_sva **sva_handle_p)
{
	/* Was the device deleted while file handle is open? */
	if (!dev->pdev)
		return -ENODEV;

	pci_info(dev->pdev, "%s: pid %d, unbind sva_handle %p\n", __func__,
		 task_pid_nr(current), *sva_handle_p);

	if (*sva_handle_p) {
		iommu_sva_unbind_device(*sva_handle_p);
		*sva_handle_p = NULL;
	}

	return 0;
}

static long dfl_pci_sva_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct dfl_sva_dev *dev = container_of(file->f_op, struct dfl_sva_dev, mdev_fops);
	struct dfl_sva_handle *sva = file->private_data;
	long ret;

	mutex_lock(&dev->mutex);

	switch (cmd) {
	case DFL_FPGA_GET_API_VERSION:
		ret = DFL_FPGA_API_VERSION;
		break;
	case DFL_PCI_SVA_BIND_DEV:
		ret = ioctl_sva_bind_dev(dev, &sva->sva_handle);
		break;
	case DFL_PCI_SVA_UNBIND_DEV:
		ret = ioctl_sva_unbind_dev(dev, &sva->sva_handle);
		break;
	default:
		pci_info(dev->pdev, "0x%x cmd not handled", cmd);
		ret = -EINVAL;
	}

	mutex_unlock(&dev->mutex);
	return ret;
}

static const struct file_operations dfl_mdev_fops = {
	.open = dfl_pci_sva_open,
	.release = dfl_pci_sva_release,
	.unlocked_ioctl = dfl_pci_sva_ioctl,
	.owner = THIS_MODULE,
};

static int add_dfl_mdev(struct dfl_sva_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;

	snprintf(dev->mdev_name, sizeof(dev->mdev_name),
		 "dfl-pci-sva!%04x:%02x:%02x.%x",
		 pci_domain_nr(pdev->bus),
		 pdev->bus->number,
		 PCI_SLOT(pdev->devfn),
		 PCI_FUNC(pdev->devfn));

	INIT_LIST_HEAD(&dev->sva_next);
	dev->mdev_fops = dfl_mdev_fops;

	dev->mdev.minor = MISC_DYNAMIC_MINOR;
	dev->mdev.name = dev->mdev_name;
	dev->mdev.fops = &dev->mdev_fops;
	dev->mdev.mode = 0400;

	mutex_init(&dev->mutex);
	misc_register(&dev->mdev);

	return 0;
}

static void del_dfl_mdev(struct dfl_sva_dev *dev)
{
	struct dfl_sva_handle *sva;

	mutex_lock(&dev->mutex);
	pci_info(dev->pdev, "dfl-sva delete device\n");
	misc_deregister(&dev->mdev);

	list_for_each_entry(sva, &dev->sva_next, sva_next) {
		if (sva->sva_handle) {
			pci_info(dev->pdev, "dfl-sva force unbind sva_handle %p\n",
				 sva->sva_handle);
			iommu_sva_unbind_device(sva->sva_handle);
			sva->sva_handle = NULL;
		}
	}

	disable_iommu_sva_feature(dev->pdev);
	dev->pdev = NULL;

	/*
	 * If the miscdevice is not open then delete the dfl_sva_dev entry.
	 * The entry can be deleted even though dev->mutex is held. The mutex
	 * is inside the memory being freed.
	 *
	 * If there is an open handle to miscdevice, keep the dfl_sva_dev.
	 * It will be freed when the file is closed.
	 */
	if (list_empty(&dev->sva_next))
		kfree(dev);
	else
		mutex_unlock(&dev->mutex);
}

static inline bool is_dfl_device(struct pci_dev *pdev)
{
	return pdev->vendor == PCI_VENDOR_ID_INTEL &&
	       (pdev->device == PCIE_DEVICE_ID_INTEL_DFL ||
		pdev->device == PCIE_DEVICE_ID_INTEL_DFL_VF);
}

/*
 * Consider adding a new device. This is called both by new dfl-pci probes
 * and from the PCIe bus notifier.
 */
static void dfl_pci_sva_add_dev(struct pci_dev *pdev)
{
	int ret;
	struct dfl_sva_dev *cur;

	/*
	 * Consider new DFL and DFL_VF devices, adding them to dfl_dev_list
	 * if they support shared virtual addressing.
	 */
	if (!is_dfl_device(pdev))
		return;

	mutex_lock(&dfl_dev_list_mutex);
	/* Nothing to do if the device was already added */
	list_for_each_entry(cur, &dfl_dev_list, pdev_next) {
		if (cur->pdev == pdev)
			goto out_unlock;
	}

	/* Manage only devices with SVA features (returns 0 here) */
	ret = enable_iommu_sva_feature(pdev);
	if (ret)
		goto out_unlock;

	cur = kzalloc(sizeof(struct dfl_sva_dev), GFP_KERNEL);
	if (!cur)
		goto out_disable;

	pci_info(pdev, "dfl-sva add device\n");
	cur->pdev = pdev;

	ret = add_dfl_mdev(cur);
	if (ret) {
		kfree(cur);
		goto out_disable;
	}

	list_add(&cur->pdev_next, &dfl_dev_list);
	mutex_unlock(&dfl_dev_list_mutex);

	return;

out_disable:
	disable_iommu_sva_feature(pdev);
out_unlock:
	mutex_unlock(&dfl_dev_list_mutex);
}

static void dfl_pci_sva_del_dev(struct pci_dev *pdev)
{
	struct dfl_sva_dev *cur;

	if (is_dfl_device(pdev)) {
		mutex_lock(&dfl_dev_list_mutex);
		list_for_each_entry(cur, &dfl_dev_list, pdev_next) {
			if (cur->pdev == pdev) {
				list_del(&cur->pdev_next);
				del_dfl_mdev(cur);
				break;
			}
		}
		mutex_unlock(&dfl_dev_list_mutex);
	}
}

/*
 * Monitor PCIe bus events so that DFL devices will be updated even if
 * they are bound to vfio-pci instead of dfl-pci.
 */
static int sva_bus_notifier(struct notifier_block *nb,
			    unsigned long action, void *data)
{
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);

	if (action == BUS_NOTIFY_ADD_DEVICE || action == BUS_NOTIFY_BIND_DRIVER)
		dfl_pci_sva_add_dev(pdev);
	if (action == BUS_NOTIFY_DEL_DEVICE)
		dfl_pci_sva_del_dev(pdev);

	return 0;
}

static int sva_init_dev(struct device *dev, void *data)
{
	dfl_pci_sva_add_dev(to_pci_dev(dev));
	return 0;
}

static int __init dfl_pci_sva_init_module(void)
{
	int ret;

	INIT_LIST_HEAD(&dfl_dev_list);
	sva_nb.notifier_call = sva_bus_notifier;
	ret = bus_register_notifier(&pci_bus_type, &sva_nb);
	if (ret)
		return ret;

	/*
	 * Discover devices already added. Devices added later will be detected
	 * by the notifier.
	 */
	return bus_for_each_dev(&pci_bus_type, NULL, NULL, sva_init_dev);
}

static void __exit dfl_pci_sva_cleanup_module(void)
{
	struct dfl_sva_dev *cur, *tmp;

	bus_unregister_notifier(&pci_bus_type, &sva_nb);

	mutex_lock(&dfl_dev_list_mutex);
	list_for_each_entry_safe(cur, tmp, &dfl_dev_list, pdev_next) {
		del_dfl_mdev(cur);
	}

	INIT_LIST_HEAD(&dfl_dev_list);
	mutex_unlock(&dfl_dev_list_mutex);
}

module_init(dfl_pci_sva_init_module);
module_exit(dfl_pci_sva_cleanup_module);

MODULE_DESCRIPTION("FPGA DFL PCIe Shared Virtual Addressing Device Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
