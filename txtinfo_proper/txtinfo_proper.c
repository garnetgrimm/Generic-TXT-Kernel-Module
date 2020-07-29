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

#define SL_DIR_ENTRY 7
#define SL_FS_ENTRIES 8

#define TXT_CR_STS			0x0000
#define TXT_CR_ESTS			0x0008
#define TXT_CR_ERRORCODE		0x0030
#define TXT_CR_CMD_RESET		0x0038
#define TXT_CR_CMD_CLOSE_PRIVATE	0x0048
#define TXT_CR_DIDVID			0x0110
#define TXT_CR_VER_EMIF			0x0200
#define TXT_CR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXT_CR_SINIT_BASE		0x0270
#define TXT_CR_SINIT_SIZE		0x0278
#define TXT_CR_MLE_JOIN			0x0290
#define TXT_CR_HEAP_BASE		0x0300
#define TXT_CR_HEAP_SIZE		0x0308
#define TXT_CR_SCRATCHPAD		0x0378
#define TXT_CR_CMD_OPEN_LOCALITY1	0x0380
#define TXT_CR_CMD_CLOSE_LOCALITY1	0x0388
#define TXT_CR_CMD_OPEN_LOCALITY2	0x0390
#define TXT_CR_CMD_CLOSE_LOCALITY2	0x0398
#define TXT_CR_CMD_SECRETS		0x08e0
#define TXT_CR_CMD_NO_SECRETS		0x08e8
#define TXT_CR_E2STS			0x08f0

#define MSG_BUFFER_LEN 22
#define MSG_ERROR "Mapping Error\n"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garnet Grimm");
MODULE_DESCRIPTION("Expose txt registers to userspace via securityfs.");
MODULE_VERSION("0.01");

static struct dentry *fs_entries[SL_FS_ENTRIES];

void __iomem *txt;

static void txt_info_to_buffer(unsigned int offset, size_t size, char* buf) {
	void __iomem *txt;
	char *format;
	u64 sample;
	memset(buf,0,sizeof(char)*MSG_BUFFER_LEN);
	txt = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES * PAGE_SIZE);	
	if(!txt) {
		snprintf(buf, MSG_BUFFER_LEN, MSG_ERROR);
		pr_err("Error with ioremap\n");
		return;
	}
	memcpy_fromio(&sample, txt + offset, size); 
	iounmap(txt);
	switch (size) {
		case sizeof(u8):
			format = "8:%#04llx\n";
			break;
		case sizeof(u16):
			format = "1:%#06llx\n";
			break;
		case sizeof(u32):
			format = "3:%#010llx\n";
			break;
		case sizeof(u64):
			format = "6:%#018llx\n";
			break;
		default:
			format = "invalid\n";
	}
	snprintf(buf, MSG_BUFFER_LEN, format, sample);	
}

#define DECLARE_PUB_READ(reg_name, reg_offset, reg_size)					\
static ssize_t reg_name##_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {	\
	char msg_buffer[MSG_BUFFER_LEN];							\
	txt_info_to_buffer(reg_offset, reg_size, msg_buffer);					\
	printk(KERN_INFO "%s", msg_buffer);							\
	return simple_read_from_buffer(buffer, len, offset, &msg_buffer, MSG_BUFFER_LEN);	\
}												\
static const struct file_operations reg_name##_ops = {						\
	.read = reg_name##_read,								\
};

DECLARE_PUB_READ(sts,TXT_CR_STS,sizeof(u64));
DECLARE_PUB_READ(ests,TXT_CR_ESTS,sizeof(u8));
DECLARE_PUB_READ(errorcode,TXT_CR_ERRORCODE,sizeof(u32));
DECLARE_PUB_READ(didvid,TXT_CR_DIDVID,sizeof(u64));
DECLARE_PUB_READ(e2sts,TXT_CR_E2STS,sizeof(u64));
DECLARE_PUB_READ(ver_emif,TXT_CR_VER_EMIF,sizeof(u32));
DECLARE_PUB_READ(scratchpad,TXT_CR_SCRATCHPAD,sizeof(u64));

static int __init start_security(void)
{
	printk(KERN_INFO "Starting security module...\n");
	fs_entries[SL_DIR_ENTRY] = securityfs_create_dir("securelaunch",NULL);
	fs_entries[0] = securityfs_create_file("txt_sts", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &sts_ops); 
	fs_entries[1] = securityfs_create_file("txt_ests", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &ests_ops); 
	fs_entries[2] = securityfs_create_file("txt_errorcode", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &errorcode_ops); 
	fs_entries[3] = securityfs_create_file("txt_didvid", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &didvid_ops); 
	fs_entries[4] = securityfs_create_file("txt_ver_emif", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &ver_emif_ops); 
	fs_entries[5] = securityfs_create_file("txt_scratchpad", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &scratchpad_ops); 
	fs_entries[6] = securityfs_create_file("txt_e2sts", S_IRUSR | S_IRGRP, fs_entries[SL_DIR_ENTRY], NULL, &e2sts_ops); 
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
