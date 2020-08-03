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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garnet Grimm");
MODULE_DESCRIPTION("Expose txt registers to userspace via securityfs.");
MODULE_VERSION("0.01");

#define MSG_BUFFER_LEN 20
#define SL_FS_ENTRIES		11
#define SL_ROOT_DIR_ENTRY	SL_FS_ENTRIES - 1 /* root directory node must be last */
#define SL_TXT_DIR_ENTRY	SL_FS_ENTRIES - 2 
#define SL_TXT_ENTRY_COUNT 		7

static struct dentry *fs_entries[SL_FS_ENTRIES];

void __iomem *txt;

static long txt_info_to_buffer(unsigned int offset, size_t size, char* buf) {
	void __iomem *txt;
	u64 reg_value;
	memset(buf,0,sizeof(char)*MSG_BUFFER_LEN);
	txt = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES * PAGE_SIZE);	
	if(IS_ERR(txt)) {
		return PTR_ERR(txt);
	}
	memcpy_fromio(&reg_value, txt + offset, size); 
	iounmap(txt);
	switch (size) {
		case sizeof(u8):
			snprintf(buf, MSG_BUFFER_LEN, "%#04x\n", (u8) reg_value);	
			break;
		case sizeof(u16):
			snprintf(buf, MSG_BUFFER_LEN, "%#06x\n", (u16) reg_value);
			break;
		case sizeof(u32):
			snprintf(buf, MSG_BUFFER_LEN, "%#010x\n", (u32) reg_value);
			break;
		case sizeof(u64):
			snprintf(buf, MSG_BUFFER_LEN, "%#018llx\n", (u64) reg_value);
			break;
		default:
			return -ENXIO;
	}
	return 0;
}


#define DECLARE_PUB_READ(reg_name, reg_offset, reg_size)                                        \
static ssize_t txt_##reg_name##_read(struct file *flip, char __user *buffer,                    \
                size_t len, loff_t *offset) {                                                   \
        char msg_buffer[MSG_BUFFER_LEN];                                                        \
        memset(msg_buffer, 0, MSG_BUFFER_LEN);                                                  \
        txt_info_to_buffer(reg_offset, reg_size, msg_buffer);                                   \
        return simple_read_from_buffer(buffer, len, offset, &msg_buffer, MSG_BUFFER_LEN);       \
}                                                                                               \
static const struct file_operations reg_name##_ops = {                                          \
        .read = txt_##reg_name##_read,                                                          \
};

DECLARE_PUB_READ(sts,TXT_CR_STS,sizeof(u64));
DECLARE_PUB_READ(ests,TXT_CR_ESTS,sizeof(u8));
DECLARE_PUB_READ(errorcode,TXT_CR_ERRORCODE,sizeof(u32));
DECLARE_PUB_READ(didvid,TXT_CR_DIDVID,sizeof(u64));
DECLARE_PUB_READ(e2sts,TXT_CR_E2STS,sizeof(u64));
DECLARE_PUB_READ(ver_emif,TXT_CR_VER_EMIF,sizeof(u32));
DECLARE_PUB_READ(scratchpad,TXT_CR_SCRATCHPAD,sizeof(u64));

struct sfs_file {
    int parent;
    const char *name;
    const struct file_operations *fops;
};

static const struct sfs_file sl_files[] = {
    { SL_TXT_DIR_ENTRY, "sts", &sts_ops },
    { SL_TXT_DIR_ENTRY, "ests", &ests_ops },
    { SL_TXT_DIR_ENTRY, "errorcode", &errorcode_ops },
    { SL_TXT_DIR_ENTRY, "didvid", &didvid_ops },
    { SL_TXT_DIR_ENTRY, "ver_emif", &ver_emif_ops },
    { SL_TXT_DIR_ENTRY, "scratchpad", &scratchpad_ops },
    { SL_TXT_DIR_ENTRY, "e2sts", &e2sts_ops }
};

static int sl_create_file(int entry, int parent, const char *name, const struct file_operations *ops) {
		if (entry < 0 || entry > SL_TXT_DIR_ENTRY) 
			return -1;
		fs_entries[entry] = securityfs_create_file(name, S_IRUSR | S_IRGRP, fs_entries[parent], NULL, ops);
		if (IS_ERR(fs_entries[entry])) {
			pr_err("Error creating securityfs %s file\n", name);
			return PTR_ERR(fs_entries[entry]);
		} else { 
			return 0;
		}
	}

static long expose_securityfs(void)
{
	long ret = 0;
	int i = 0;

	fs_entries[SL_ROOT_DIR_ENTRY] = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(fs_entries[SL_ROOT_DIR_ENTRY])) {
		pr_err("Error creating securityfs sl_evt_log directory\n");
		ret = PTR_ERR(fs_entries[SL_ROOT_DIR_ENTRY]);
		goto err;
	}

	if (true) {
		fs_entries[SL_TXT_DIR_ENTRY] = securityfs_create_dir("txt", fs_entries[SL_ROOT_DIR_ENTRY]);
		if (IS_ERR(fs_entries[SL_TXT_DIR_ENTRY])) {
			pr_err("Error creating securityfs sl_evt_log directory\n");
			ret = PTR_ERR(fs_entries[SL_TXT_DIR_ENTRY]);
			goto err;
		}
	
		for(i = 0; i < SL_TXT_ENTRY_COUNT; i++) {
			ret = sl_create_file(SL_TXT_DIR_ENTRY - 1 - i, sl_files[i].parent, sl_files[i].name, sl_files[i].fops);
			if (ret)
				goto err_dir;
		}
	}

	/*
	if (sl_evtlog.addr > 0) {
		ret = sl_create_file(0, sl_root_dir_entry, sl_evtlog.name, &sl_evtlog_ops);
		if (ret)
			goto err_dir;
	}*/

	return 0;

err_dir:
	for(i = 0; i <= SL_ROOT_DIR_ENTRY; i++)
		securityfs_remove(fs_entries[i]);
err:
	return ret;
}

static void teardown_securityfs(void)
{
	int i;
	for (i = 0; i < SL_FS_ENTRIES; i++)
		securityfs_remove(fs_entries[i]);
}

static int __init start_security(void)
{
	printk(KERN_INFO "Starting security module...\n");
	expose_securityfs();
	printk(KERN_INFO "Started security module success!\n");
	return 0;
}

static void __exit stop_security(void) {
	teardown_securityfs();
	printk(KERN_INFO "Succesfully ended security module\n");
}

module_init(start_security);
module_exit(stop_security);
