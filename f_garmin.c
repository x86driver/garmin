/*
 * f_garmin.c -- Garmin USB function driver
 * 
 * Copyright (C) 2010 by Doremi Lin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/usb/composite.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/fs.h>

//#include "epautoconf.c"
//#include "composite.c"
//#include "config.c"
//#include "usbstring.c"

MODULE_LICENSE("GPL");

struct f_garmin {
	spinlock_t lock;
	struct usb_function func;
	struct usb_ep *in_ep;
	struct usb_ep *out_ep;
};

struct usb_request *global_in_req, *global_out_req;
static struct f_garmin *_garmin_dev;
static unsigned qlen = 32;
unsigned int buflen = 4096;

#if 0
static struct usb_gadget_strings garmin_string_table = {
	.language		= 0x0409, /* en-us */
	.strings		= garmin_string_defs,
};

static struct usb_gadget_strings *garmin_strings[] = {
	&garmin_string_table,
	NULL,
};
#endif

static struct usb_endpoint_descriptor hs_garmin_in_desc = {
        .bLength		= USB_DT_ENDPOINT_SIZE,
        .bDescriptorType	= USB_DT_ENDPOINT,
        .bmAttributes		= USB_ENDPOINT_XFER_BULK,
//	.bEndpointAddress	= USB_DIR_IN,
        .wMaxPacketSize		= __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_garmin_out_desc = {
        .bLength		= USB_DT_ENDPOINT_SIZE,
        .bDescriptorType	= USB_DT_ENDPOINT,
        .bmAttributes		= USB_ENDPOINT_XFER_BULK,
//	.bEndpointAddress	= USB_DIR_OUT,
        .wMaxPacketSize		= __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor fs_garmin_in_desc = {
        .bLength                = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType        = USB_DT_ENDPOINT,
        .bmAttributes           = USB_ENDPOINT_XFER_BULK,
        .bEndpointAddress       = USB_DIR_IN,
};

static struct usb_endpoint_descriptor fs_garmin_out_desc = {
        .bLength                = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType        = USB_DT_ENDPOINT,
        .bmAttributes           = USB_ENDPOINT_XFER_BULK,
        .bEndpointAddress       = USB_DIR_OUT,
};

static struct usb_interface_descriptor garmin_intf = {
        .bLength		= sizeof(garmin_intf),
        .bDescriptorType	= USB_DT_INTERFACE,
        .bNumEndpoints		= 2, /* in,out, WARNING: without int */
        .bInterfaceClass	= 0xFF,
	.bInterfaceSubClass	= 0xFF,
	.bInterfaceProtocol	= 0xFF,
        /* .iInterface = DYNAMIC */
};

static struct usb_descriptor_header *hs_garmin_descs[] = {
        (struct usb_descriptor_header *) &garmin_intf,
        (struct usb_descriptor_header *) &hs_garmin_in_desc,
        (struct usb_descriptor_header *) &hs_garmin_out_desc,
        NULL,
};

static struct usb_descriptor_header *fs_garmin_descs[] = {
        (struct usb_descriptor_header *) &garmin_intf,
        (struct usb_descriptor_header *) &fs_garmin_in_desc,
        (struct usb_descriptor_header *) &fs_garmin_out_desc,
        NULL,
};

static inline struct f_garmin *func_to_garmin(struct usb_function *f)
{
	return container_of(f, struct f_garmin, func);
}

/**
 * @disable: (REQUIRED) Indicates the function should be disabled.  Reasons
 *      include host resetting or reconfiguring the gadget, and disconnection.
 */
static void garmin_disable(struct usb_function *f)
{

} 

struct usb_request *alloc_ep_req(struct usb_ep *ep)
{
        struct usb_request      *req;

        req = usb_ep_alloc_request(ep, GFP_ATOMIC);
        if (req) {
                req->length = buflen;
                req->buf = kmalloc(buflen, GFP_ATOMIC);
                if (!req->buf) {
                        usb_ep_free_request(ep, req);
                        req = NULL;
                }
        }
        return req;
}

static void garmin_out_complete(struct usb_ep *ep, struct usb_request *req)
{
//        struct f_garmin         *garmin = ep->driver_data;
//        struct usb_composite_dev *cdev = garmin->func.config->cdev;
	printk(KERN_ALERT "I got a OUT request, %d!!\n", req->actual);
}

static void garmin_in_complete(struct usb_ep *ep, struct usb_request *req)
{
//        struct f_garmin         *garmin = ep->driver_data;
//        struct usb_composite_dev *cdev = garmin->func.config->cdev;
        printk(KERN_ALERT "I got a IN request, %d!!\n", req->actual);
}

/**
 * @bind: Before the gadget can register, all of its functions bind() to the
 *      available resources including string and interface identifiers used
 *      in interface or class descriptors; endpoints; I/O buffers; and so on.
 */
static int __init garmin_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_garmin *garmin	= func_to_garmin(f);
	int id;

	id = usb_interface_id(c, f);
	if (id < 0)
		return id;

	garmin_intf.bInterfaceNumber = id;
	garmin->in_ep = usb_ep_autoconfig(cdev->gadget, &fs_garmin_in_desc);
	if (!garmin->in_ep) {
autoconf_fail:
		ERROR(cdev, "%s: can't autoconfig on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	garmin->in_ep->driver_data = cdev;

	garmin->out_ep = usb_ep_autoconfig(cdev->gadget, &fs_garmin_out_desc);
	if (!garmin->out_ep)
		goto autoconf_fail;
	garmin->out_ep->driver_data = cdev;

	if (gadget_is_dualspeed(c->cdev->gadget)) {
		hs_garmin_in_desc.bEndpointAddress =
			fs_garmin_in_desc.bEndpointAddress;
		hs_garmin_out_desc.bEndpointAddress =
			fs_garmin_out_desc.bEndpointAddress;
	}

	printk(KERN_ALERT "%s speed %s: IN/%d, OUT/%d\n",
		gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
		f->name, hs_garmin_in_desc.bEndpointAddress, hs_garmin_out_desc.bEndpointAddress);

        /* 分配一串讀取緩衝區以及馬上把他們 queue 起來！
         * 我們最多緩衝 qlen 個傳送, 較少如果任何需要多過 buflen
         * 個位元組每個。
         */

	return 0;
}

static int enable_garmin(struct usb_composite_dev *cdev, struct f_garmin *garmin)
{
	const struct usb_endpoint_descriptor	*in, *out;
	struct usb_ep				*ep;
	int					result;
	struct usb_request			*req;

	in = ep_choose(cdev->gadget, &hs_garmin_in_desc, &fs_garmin_in_desc);
	out = ep_choose(cdev->gadget, &hs_garmin_out_desc, &fs_garmin_out_desc);

	/* 這個端點透過 IN 寫入資料回去主機 */
	ep = garmin->in_ep;
	result = usb_ep_enable(ep, in);
	if (result < 0)
		return result;
	ep->driver_data = garmin;

	/* 這端點僅僅讀取 OUT 封包 */
	ep = garmin->out_ep;
	result = usb_ep_enable(ep, out);
	if (result < 0) {
		ep = garmin->in_ep;
		usb_ep_disable(ep);
		ep->driver_data = NULL;
		return result;
	}
	ep->driver_data = garmin;

        /* 一開始要做的事情: 分配 req, req->buf, 設定 complete function */
        req = alloc_ep_req(garmin->out_ep);
        if (req) {
                req->complete = garmin_out_complete;
		result = usb_ep_queue(garmin->out_ep, req, GFP_ATOMIC);
		if (result != 0) {
			printk(KERN_ALERT "usb_ep_queue error!\n");
		}
                global_out_req = req;
        }

        req = alloc_ep_req(garmin->in_ep);
        if (req) {
                req->complete = garmin_in_complete;
		result = usb_ep_queue(garmin->in_ep, req, GFP_ATOMIC);
		if (result != 0) {
			printk(KERN_ALERT "usb_ep_queue IN error\n");
		}
		global_in_req = req;
        }

	printk(KERN_ALERT "%s enabled\n", garmin->func.name);
	return result;
}

/**
 * @set_alt: (REQUIRED) Reconfigures altsettings; function drivers may
 *      initialize usb_ep.driver data at this time (when it is used).
 *      Note that setting an interface to its current altsetting resets
 *      interface state, and that all interfaces have a disabled state.
 */
static int garmin_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_garmin *garmin = func_to_garmin(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	if (garmin->in_ep->driver_data) {
		printk(KERN_ALERT "disable...\n");
	}
	return enable_garmin(cdev, garmin);
}

int __init garmin_bind_config(struct usb_composite_dev *cdev,
				struct usb_configuration *c)
{
	struct f_garmin *garmin;
	int status;

	garmin = kzalloc(sizeof(struct f_garmin), GFP_KERNEL);
	if (garmin == NULL)
		return -ENOMEM;

	spin_lock_init(&garmin->lock);

	garmin->func.name = "garmin";
//	garmin->func.strings = garmin_strings;
	garmin->func.bind = garmin_bind;
	garmin->func.set_alt = garmin_set_alt;
	garmin->func.disable = garmin_disable;
	garmin->func.descriptors = fs_garmin_descs;
	garmin->func.hs_descriptors = hs_garmin_descs;

	_garmin_dev = garmin;

	status = usb_add_function(c, &garmin->func);
	if (status)
		kfree(garmin);
	return status;
}

static int garmin_open(struct inode *ip, struct file *fp)
{
        printk(KERN_INFO "garmin_open\n");
	fp->private_data = _garmin_dev;
        return 0;
}

static int garmin_release(struct inode *ip, struct file *fp)
{
        printk(KERN_INFO "garmin_release\n");
        return 0;
}

static ssize_t garmin_read(struct file *fp, char __user *buf,
                                size_t count, loff_t *pos)
{
	struct usb_request *req = global_out_req;
	struct f_garmin *dev = fp->private_data;
	int ret;
	int i;
	char buffer[16];


	memcpy(&buffer[0], req->buf, req->actual);
	buffer[req->actual] = 0;
	printk(KERN_ALERT "%s", buffer);

	/* Prepare for next request */
	ret = usb_ep_queue(dev->out_ep, req, GFP_ATOMIC);
	if (ret < 0) {
		return -EIO;
	}
	return 0;
}


static struct file_operations garmin_fops = {
        .owner = THIS_MODULE,
        .read = garmin_read,
	.write = NULL,
        .open = garmin_open,
        .release = garmin_release,
};

static struct miscdevice garmin_device = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "garmin",
        .fops = &garmin_fops,
};

int __init garmin_function_add(struct usb_composite_dev *cdev,
        struct usb_configuration *c)
{
        int ret = garmin_bind_config(cdev, c);

	ret = misc_register(&garmin_device);

        return ret;
}
