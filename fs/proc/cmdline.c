#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#ifdef CONFIG_INITRAMFS_IGNORE_SKIP_FLAG
#include <asm/setup.h>
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
extern struct static_key_false susfs_is_fake_cmdline_or_bootconfig_buffer_set;
extern void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);
#endif

#ifdef CONFIG_LIMITLESS
static void replace_param(char *str, const char *old_str, const char *new_str) {
    char *pos = strstr(str, old_str);
    if (pos) {
        memcpy(pos, new_str, strlen(new_str));
    }
}

/* Limitless Loader */
static void spoof_bootloader_params(char *buf) {
    replace_param(buf, "androidboot.verifiedbootstate=orange", "androidboot.verifiedbootstate=green ");
    replace_param(buf, "androidboot.verifiedbootstate=yellow", "androidboot.verifiedbootstate=green ");
    replace_param(buf, "androidboot.flash.locked=0", "androidboot.flash.locked=1");
    replace_param(buf, "androidboot.vbmeta.device_state=unlocked", "androidboot.vbmeta.device_state=locked  ");
}
#endif

#ifdef CONFIG_INITRAMFS_IGNORE_SKIP_FLAG
#define INITRAMFS_STR_FIND "skip_initramf"
#define INITRAMFS_STR_REPLACE "want_initramf"
#define INITRAMFS_STR_LEN (sizeof(INITRAMFS_STR_FIND) - 1)

static char proc_command_line[COMMAND_LINE_SIZE];

static void proc_command_line_init(void) {
	char *offset_addr;

	strcpy(proc_command_line, saved_command_line);

	offset_addr = strstr(proc_command_line, INITRAMFS_STR_FIND);
	if (offset_addr)
		memcpy(offset_addr, INITRAMFS_STR_REPLACE, INITRAMFS_STR_LEN);

#ifdef CONFIG_LIMITLESS
	spoof_bootloader_params(proc_command_line);
#endif
}
#endif

static int cmdline_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)) {
		susfs_spoof_cmdline_or_bootconfig(m);
        seq_putc(m, '\n');
        return 0;
    }
#endif

#ifdef CONFIG_INITRAMFS_IGNORE_SKIP_FLAG
	seq_printf(m, "%s\n", proc_command_line);
#else
#ifdef CONFIG_LIMITLESS
	char buf[COMMAND_LINE_SIZE];
	strlcpy(buf, saved_command_line, sizeof(buf));
	spoof_bootloader_params(buf);
	seq_printf(m, "%s\n", buf);
#else
	seq_printf(m, "%s\n", saved_command_line);
#endif
#endif
	return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
	.open		= cmdline_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_cmdline_init(void)
{
#ifdef CONFIG_INITRAMFS_IGNORE_SKIP_FLAG
	proc_command_line_init();
#endif

	proc_create("cmdline", 0, NULL, &cmdline_proc_fops);
	return 0;
}
fs_initcall(proc_cmdline_init);
