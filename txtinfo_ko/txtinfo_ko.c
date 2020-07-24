#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/device.h>

//for ioremap.. etc
#include <linux/io.h>

//for open
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/fs.h>

#define TXT_PUB_CR_BASE	    0xfed30000
#define TXT_PUB_CR_SIZE	    0x10000
#define TXT_PUB_CR_INDEX    0
#define DEMO_ERROR 0xc0008004
#define TXT_STS_OFFSET		0x000
#define TXT_ESTS_OFFSET		0x008
#define TXT_ERRORCODE_OFFSET	0x030
#define TXT_VER_FSBIF_OFFSET	0x100
#define TXT_DIDVID_OFFSET	0x110
#define TXT_VER_QPIIF_OFFSET	0x200

#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garnet (GBOI) Grimm");
MODULE_DESCRIPTION("Expose securityfs.");
MODULE_VERSION("0.01");

static struct dentry* folder;
static struct dentry* file;

static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

void __iomem *txt;

static ssize_t log_write(struct file *file, const char __user *buf, size_t datalen, loff_t *ppos) {
	printk(KERN_INFO "WRITIN\n");
	return -EINVAL;
}

/* When a process reads from our device, this gets called. */
static ssize_t log_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
 int bytes_read = 0;
 /* If we’re at the end, loop back to the beginning */
 if (*msg_ptr == 0) {
 	//msg_ptr = msg_buffer;
	return 0;
 }
 /* Put data in the buffer */
 while (len && *msg_ptr) {
 /* Buffer is in user data, not kernel, so you can’t just reference
 * with a pointer. The function put_user handles this for us */
 put_user(*(msg_ptr++), buffer++);
 len--;
 bytes_read++;
 }
 return bytes_read;
}

static const struct file_operations log_ops = {
	.write = log_write,
	.read = log_read
};
static int __init start_security(void)
{
	strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
	msg_ptr = msg_buffer;
	printk(KERN_INFO "Starting security module...\n");
	printk(KERN_INFO "Log is %p\n", (void *)msg_ptr);
	folder = securityfs_create_dir("supersecret",NULL);
	file = securityfs_create_file("logfile", S_IRUSR | S_IRGRP, folder, NULL, &log_ops); 
	printk(KERN_INFO "Started security module success!\n");

	return 0;
}

static void __exit stop_security(void) {
	printk(KERN_INFO "Ended security module\n");
	securityfs_remove(file);
	securityfs_remove(folder);
}

module_init(start_security);
module_exit(stop_security);
