/*
 * This code exposes the following registers 
  +----------------+----------------------------+------+----------------+
 * |    Register    |        Description         | Size | Manual Section |
 * +----------------+----------------------------+------+----------------+
 * | TXT.STS        | Status                     |   64 | B.1.1          |
 * | TXT.ESTS       | Error Status               |   08 | B.1.2          |
 * | TXT.ERRORCODE  | Error Code                 |   32 | B.1.3          |
 * | TXT.DIDVID     | TXT Device ID              |   64 | B.1.7          |
 * | TXT.VER.EMIF   | EMC Version Numer Register |   32 | B.1.8          |
 * | TXT.SCRATCHPAD | ACM_POLICY_STATUS          |   64 | B.1.16         |
 * | TXT.E2STS      | Extended Error Status      |   64 | B.1.24         |
 * +----------------+----------------------------+------+----------------+
*/
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

#define TXT_PUB_CONFIG_REGS_BASE  0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE 0xfed20000
#define TXT_NR_CONFIG_PAGES ((TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

#define SL_DIR_ENTRY 0
#define SL_FS_ENTRIES 8

#define TXT_STS_OFFSET		0x000
#define TXT_ESTS_OFFSET		0x008
#define TXT_ERRORCODE_OFFSET	0x030
#define TXT_DIDVID_OFFSET	0x110
#define TXT_VER_EMIF_OFFSET	0x200
#define TXT_SCRATCHPAD_OFFSET	0x378
#define TXT_E2STS_OFFSET	0x8f0

#define MSG_BUFFER_LEN 16

#define DECLARE_PUB_SHOW(reg_name, reg_offset, reg_size)					\
static ssize_t reg_name##_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {	\
	get_txt_info(reg_offset, reg_size);							\
	return simple_read_from_buffer(buffer, len, offset, &msg_buffer, MSG_BUFFER_LEN);	\
}												\
static const struct file_operations reg_name##_ops = {						\
	.read = reg_name##_read,								\
	.write = log_write									\
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garnet Grimm");
MODULE_DESCRIPTION("Expose txt registers to userspace via securityfs.");
MODULE_VERSION("0.01");

static struct dentry *fs_entries[SL_FS_ENTRIES];

static char msg_buffer[MSG_BUFFER_LEN];

void __iomem *txt;

static ssize_t log_write(struct file *file, const char __user *buf, size_t datalen, loff_t *ppos) {
	return -EINVAL;
}

static u64 get_txt_info(unsigned int offset, int size) {
	void __iomem *txt;
	u64 sample;
	txt = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES * PAGE_SIZE);	
	if(!txt) {
		printk(KERN_INFO "Error with ioremap\n");
	}
	memcpy_fromio(&sample, txt + offset, size); 
	iounmap(txt);
	snprintf(msg_buffer, MSG_BUFFER_LEN, "0x%08llx\n", sample);
	return sample;	
}

DECLARE_PUB_SHOW(sts,TXT_STS_OFFSET,sizeof(u64));
DECLARE_PUB_SHOW(ests,TXT_ESTS_OFFSET,sizeof(u8));
DECLARE_PUB_SHOW(errorcode,TXT_ERRORCODE_OFFSET,sizeof(u32));
DECLARE_PUB_SHOW(didvid,TXT_DIDVID_OFFSET,sizeof(u64));
DECLARE_PUB_SHOW(ver_emif,TXT_VER_EMIF_OFFSET,sizeof(u32));
DECLARE_PUB_SHOW(scratchpad,TXT_SCRATCHPAD_OFFSET,sizeof(u64));
DECLARE_PUB_SHOW(e2sts,TXT_E2STS_OFFSET,sizeof(u64));

static int __init start_security(void)
{
	printk(KERN_INFO "Starting security module...\n");
	fs_entries[SL_DIR_ENTRY] = securityfs_create_dir("securelaunch",NULL);
	fs_entries[1] = securityfs_create_file("sts", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &sts_ops); 
	fs_entries[2] = securityfs_create_file("ests", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &ests_ops); 
	fs_entries[3] = securityfs_create_file("errorcode", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &errorcode_ops); 
	fs_entries[4] = securityfs_create_file("didvid", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &didvid_ops); 
	fs_entries[5] = securityfs_create_file("ver_emif", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &ver_emif_ops); 
	fs_entries[6] = securityfs_create_file("scratchpad", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &scratchpad_ops); 
	fs_entries[7] = securityfs_create_file("e2sts", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &e2sts_ops); 
	printk(KERN_INFO "Started security module success!\n");
	return 0;
}

static void __exit stop_security(void) {
	int i;
	printk(KERN_INFO "Ending security module...\n");
	for(i = 0; i < SL_FS_ENTRIES; i++) {
		securityfs_remove(fs_entries[i]);
	}
	printk(KERN_INFO "Succesfully ended security module\n");
}

module_init(start_security);
module_exit(stop_security);
