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
#include <linux/poll.h>
#include <linux/semaphore.h>

MODULE_LICENSE("GPL");

#define REQ_SIZE 32
struct f_garmin {
	struct semaphore sem_r, sem_w;
	spinlock_t spinlock;
	wait_queue_head_t wait_r, wait_w;

	struct usb_function func;

        struct usb_ep *in_ep;
        struct usb_ep *out_ep;
        struct usb_ep *int_ep;

        struct list_head req_head_in;
        struct list_head req_head_out_busy;
	struct list_head req_head_out_free;
        struct list_head req_head_int;

	struct usb_request *req_array_in[REQ_SIZE];
	struct usb_request *req_array_out[REQ_SIZE];
	struct usb_request *req_array_int[REQ_SIZE];

	struct usb_request *cur_read_req;
	unsigned int cur_read_count;
	unsigned char *cur_read_buf;
};

static struct f_garmin *_garmin_dev;
unsigned int buflen = 4096;

static inline void QUEUE(struct usb_request *p, struct list_head *head)
{
	unsigned long flags;

	spin_lock_irqsave(&_garmin_dev->spinlock, flags);
        list_add_tail(&p->list, head);
	spin_unlock_irqrestore(&_garmin_dev->spinlock, flags);
}

static inline struct usb_request *DEQUE(struct list_head *head)
{
        struct usb_request *tmp;
	unsigned long flags;

	spin_lock_irqsave(&_garmin_dev->spinlock, flags);
	if (list_empty(head)) {
		spin_unlock_irqrestore(&_garmin_dev->spinlock, flags);
		return NULL;
	}
        tmp = list_first_entry(head, struct usb_request, list);
        list_del(&tmp->list);
	spin_unlock_irqrestore(&_garmin_dev->spinlock, flags);
        return tmp;
}

static void init_list(void)
{
        INIT_LIST_HEAD(&_garmin_dev->req_head_in);
        INIT_LIST_HEAD(&_garmin_dev->req_head_out_busy);
	INIT_LIST_HEAD(&_garmin_dev->req_head_out_free);
        INIT_LIST_HEAD(&_garmin_dev->req_head_int);
}

static void __free_request(struct list_head *head)
{
        struct list_head *p, *n;
        struct usb_request *req;

        list_for_each_safe(p, n, head) {
                req = list_entry(p, struct usb_request, list);
                list_del(&req->list);
                kfree(req->buf);
        }
}

static void free_request(void)
{
        __free_request(&_garmin_dev->req_head_in);
        __free_request(&_garmin_dev->req_head_out_busy);
	__free_request(&_garmin_dev->req_head_out_free);
        __free_request(&_garmin_dev->req_head_int);
}

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
        .wMaxPacketSize		= __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_garmin_out_desc = {
        .bLength		= USB_DT_ENDPOINT_SIZE,
        .bDescriptorType	= USB_DT_ENDPOINT,
        .bmAttributes		= USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize		= __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_garmin_int_desc = {
        .bLength                = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType        = USB_DT_ENDPOINT,
        .bmAttributes           = USB_ENDPOINT_XFER_INT,
        .wMaxPacketSize         = __constant_cpu_to_le16(64),
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

static struct usb_endpoint_descriptor fs_garmin_int_desc = {
        .bLength                = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType        = USB_DT_ENDPOINT,
        .bmAttributes           = USB_ENDPOINT_XFER_INT,
        .bEndpointAddress       = USB_DIR_IN,
};

static struct usb_interface_descriptor garmin_intf = {
        .bLength		= sizeof(garmin_intf),
        .bDescriptorType	= USB_DT_INTERFACE,
        .bNumEndpoints		= 3, /* in,out, WARNING: without int */
        .bInterfaceClass	= 0xFF,
	.bInterfaceSubClass	= 0xff,
	.bInterfaceProtocol	= 0xff,
	.bInterfaceNumber	= 0,
        /* .iInterface = DYNAMIC */
};

static struct usb_descriptor_header *hs_garmin_descs[] = {
        (struct usb_descriptor_header *) &garmin_intf,
        (struct usb_descriptor_header *) &hs_garmin_in_desc,
        (struct usb_descriptor_header *) &hs_garmin_out_desc,
	(struct usb_descriptor_header *) &hs_garmin_int_desc,
        NULL,
};

static struct usb_descriptor_header *fs_garmin_descs[] = {
        (struct usb_descriptor_header *) &garmin_intf,
        (struct usb_descriptor_header *) &fs_garmin_in_desc,
        (struct usb_descriptor_header *) &fs_garmin_out_desc,
	(struct usb_descriptor_header *) &fs_garmin_int_desc,
        NULL,
};

static struct usb_descriptor_header *null_garmin_descs[] = {
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
	struct f_garmin *garmin = func_to_garmin(f);
	usb_ep_disable(garmin->in_ep);
	usb_ep_disable(garmin->out_ep);
	usb_ep_disable(garmin->int_ep);
} 

struct usb_request *alloc_ep_req(struct usb_ep *ep)
{
        struct usb_request      *req;

        req = usb_ep_alloc_request(ep, GFP_KERNEL);
        if (req) {
                req->length = buflen;
                req->buf = kmalloc(buflen, GFP_KERNEL);
                if (!req->buf) {
                        usb_ep_free_request(ep, req);
                        req = NULL;
                }
        }
        return req;
}

static void garmin_out_complete(struct usb_ep *ep, struct usb_request *req)
{
	int result;
	printk(KERN_ALERT "I got a OUT request, %d!!\n", req->actual);
	if (req->status != 0) {
		printk(KERN_ALERT "usb out complete error\n");
		QUEUE(req, &_garmin_dev->req_head_out_free);
	} else {
		QUEUE(req, &_garmin_dev->req_head_out_busy);
	}
	wake_up(&_garmin_dev->wait_r);
}

static void garmin_in_complete(struct usb_ep *ep, struct usb_request *req)
{
        printk(KERN_ALERT "I got a IN request, %d!!\n", req->actual);
}

static void garmin_int_complete(struct usb_ep *ep, struct usb_request *req)
{
	printk(KERN_ALERT "I got a INT request, %d!!\n", req->actual);
	QUEUE(req, &_garmin_dev->req_head_int);
	wake_up(&_garmin_dev->wait_w);
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

        garmin->out_ep = usb_ep_autoconfig(cdev->gadget, &fs_garmin_out_desc);
        if (!garmin->out_ep) {
autoconf_fail:
                ERROR(cdev, "%s: can't autoconfig on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;
        }
        garmin->out_ep->driver_data = cdev;

	garmin->in_ep = usb_ep_autoconfig(cdev->gadget, &fs_garmin_in_desc);
	if (!garmin->in_ep)
		goto autoconf_fail;
	garmin->in_ep->driver_data = cdev;

	garmin->int_ep = usb_ep_autoconfig(cdev->gadget, &fs_garmin_int_desc);
	if (!garmin->int_ep)
		goto autoconf_fail;
	garmin->int_ep->driver_data = cdev;

	if (gadget_is_dualspeed(c->cdev->gadget)) {
		hs_garmin_out_desc.bEndpointAddress =
			fs_garmin_out_desc.bEndpointAddress;
                hs_garmin_in_desc.bEndpointAddress =
                        fs_garmin_in_desc.bEndpointAddress;
		hs_garmin_int_desc.bEndpointAddress =
			fs_garmin_int_desc.bEndpointAddress;
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
	const struct usb_endpoint_descriptor	*in, *out, *INT;
	struct usb_ep				*ep;
	int					result, i;
	struct usb_request			*req;

	in = ep_choose(cdev->gadget, &hs_garmin_in_desc, &fs_garmin_in_desc);
	out = ep_choose(cdev->gadget, &hs_garmin_out_desc, &fs_garmin_out_desc);
	INT = ep_choose(cdev->gadget, &hs_garmin_int_desc, &fs_garmin_int_desc);

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

	/* 這個端點透過 IN 寫入資料回去主機 */
	ep = garmin->in_ep;
	result = usb_ep_enable(ep, in);
	if (result < 0)
		return result;
	ep->driver_data = garmin;

	/* 開啟 INT endpoint */
	result = usb_ep_enable(garmin->int_ep, INT);
	if (result < 0) {
		usb_ep_disable(garmin->int_ep);
		garmin->int_ep->driver_data = NULL;
		return result;
	}

        /* 一開始要做的事情: 分配 req, req->buf, 設定 complete function */
	for (i = 0; i < REQ_SIZE; ++i) {
	        req = garmin->req_array_out[i] = alloc_ep_req(garmin->out_ep);
	        if (req) {
        	        req->complete = garmin_out_complete;
			QUEUE(req, &garmin->req_head_out_free);
		}
	}

        req = alloc_ep_req(garmin->in_ep);
        if (req) {
                req->complete = garmin_in_complete;
        }

	/* 對於 IN 的 endpoint 應該只需要:
	 * 1. 分配 buffer
	 * 2. 設定完工函式
	 * 3. 設定全域變數 global_xx_req
	 */

	for (i = 0; i < REQ_SIZE; ++i) {
		req = garmin->req_array_int[i] = alloc_ep_req(garmin->int_ep);
		if (req) {
			req->complete = garmin_int_complete;
			QUEUE(req, &garmin->req_head_int);
		}
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

static void garmin_unbind(struct usb_configuration *c, struct usb_function *f)
{
	printk(KERN_ALERT "[doremi] garmin unbind called\n");
}

int __init garmin_bind_config(struct usb_composite_dev *cdev,
				struct usb_configuration *c)
{
	struct f_garmin *garmin;
	int status;

	garmin = kzalloc(sizeof(struct f_garmin), GFP_KERNEL);
	if (garmin == NULL)
		return -ENOMEM;

	garmin->func.name = "garmin";
//	garmin->func.strings = garmin_strings;
	garmin->func.bind = garmin_bind;
	garmin->func.unbind = garmin_unbind;
	garmin->func.set_alt = garmin_set_alt;
	garmin->func.disable = garmin_disable;
	garmin->func.descriptors = fs_garmin_descs;
	garmin->func.hs_descriptors = hs_garmin_descs;
/* 先預設都是 NULL by doremi */
//	garmin->func.descriptors = NULL;
//	garmin->func.hs_descriptors = NULL;

	_garmin_dev = garmin;

	init_MUTEX(&garmin->sem_r);
	init_MUTEX(&garmin->sem_w);
	init_waitqueue_head(&garmin->wait_r);
	init_waitqueue_head(&garmin->wait_w);
	spin_lock_init(&garmin->spinlock);
	init_list();

	/* Init variable for read request */
	garmin->cur_read_count = 0;
	garmin->cur_read_buf = NULL;

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
	int ret = 0;
	int read_byte = 0;
	struct usb_request *req;
	struct f_garmin *dev = fp->private_data;

	if (down_interruptible(&dev->sem_r)) {
		return -ERESTARTSYS;
	}

	/* 如果使用者要求的資料還沒傳完 */
	while (count > 0) {
		/* 把所有 free queue 的 req 拿出來, 丟到 usb_ep_queue */
		while ((req = DEQUE(&dev->req_head_out_free))) {
requeue:
			req->length = buflen;
			ret = usb_ep_queue(dev->out_ep, req, GFP_KERNEL);
			if (ret < 0) {
				printk(KERN_ALERT "USB error!\n");
				ret = -EIO;
				goto fail;
			}
		}

		if (dev->cur_read_count) {
			if (dev->cur_read_count < count)
				read_byte = dev->cur_read_count;
			else
				read_byte = count;

			if (copy_to_user(buf, dev->cur_read_buf, read_byte)) {
				ret = -EAGAIN;
				goto fail;
			}

			dev->cur_read_count -= read_byte;
			dev->cur_read_buf += read_byte;
			count -= read_byte;
			buf += read_byte;
			
			if (dev->cur_read_count == 0) {
				QUEUE(dev->cur_read_req, &dev->req_head_out_free);
				dev->cur_read_req = NULL;
			}
			continue;
		}

		req = NULL;
		ret = wait_event_interruptible(dev->wait_r, (req = DEQUE(&dev->req_head_out_busy)));
		if (req != NULL) {
			if (req->actual == 0)
				goto requeue;

			dev->cur_read_req = req;
			dev->cur_read_count = req->actual;
			dev->cur_read_buf = req->buf;
			printk(KERN_ALERT "First char: %c\n", dev->cur_read_buf[0]);
		}

		if (ret < 0) {
			ret = -EAGAIN;
			goto fail;
		}
	}

fail:
	up(&dev->sem_r);
	return ret;
}

static ssize_t garmin_write(struct file *fp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct f_garmin *dev = fp->private_data;
	struct usb_request *req;
	int write_byte;
	int ret = 0;

	down_interruptible(&dev->sem_w);

	while (count > 0) {
		ret = wait_event_interruptible(dev->wait_w, (req = DEQUE(&dev->req_head_int)));
		if (req != NULL) {
			if (count < buflen)
				write_byte = count;
			else
				write_byte = buflen;
		}

		if (unlikely(ret < 0)) {
			ret = -EAGAIN;
			goto fail;
		}

		if (copy_from_user(req->buf, buf, write_byte)) {
			ret = -EAGAIN;
			goto fail;
		}

		count -= write_byte;
		buf += write_byte;
		req->length = write_byte;
		
		ret = usb_ep_queue(dev->int_ep, req, GFP_KERNEL);
		if (ret < 0) {
			ret = -EIO;
			goto fail;
		}
		ret += write_byte;
	}

fail:
	up(&dev->sem_w);
	return ret;
}

static ssize_t garmin_write2(struct file *fp, const char __user *buf,
                                 size_t count, loff_t *pos)
{
	const char ESN[] = {0,0,0,0,
			    6,0,0,0,
			    4,0,0,0,
			    0x0,0x94,0x35,0x77};
	struct f_garmin *dev = fp->private_data;
	int ret;

#if 0
	if (copy_from_user(req->buf, buf, count)) {	/* 我們都假設 count 不超過 4096 */
		return -EFAULT;
	}
	req->length = count;
#endif

#if 0 //這部份是直接把 ESN 傳回去 而不管 user space 傳甚饃進來
	memcpy(req->buf, ESN, sizeof(ESN));
	req->length = sizeof(ESN);
#endif

#if 0
	ret = usb_ep_queue(dev->int_ep, req, GFP_KERNEL);
	if (ret < 0) {
		return -EIO;
	}
#endif
	return count;
}

static struct file_operations garmin_fops = {
        .owner = THIS_MODULE,
        .read = garmin_read,
	.write = garmin_write,
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

void garmin_function_enable(void)
{
        struct f_garmin *dev = _garmin_dev;

        if (dev) {
                dev->func.descriptors = fs_garmin_descs;
                dev->func.hs_descriptors = hs_garmin_descs;
        }
}

