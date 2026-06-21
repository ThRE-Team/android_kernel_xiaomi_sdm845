#include <linux/string.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/next_hide.h>

#include "mount.h"

#define uid_matches() (getuid() >= 2000)

#define MAX_HIDE_SIZE 2048

char limitless_hide_buffer[MAX_HIDE_SIZE] = {0};

static const char* const suspicious_paths[] = {
	"/system/addon.d",
	"/system/bin/install-recovery.sh",
	"/vendor/bin/install-recovery.sh",
	"/system/lib/libzygisk.so",
	"/system/lib64/libzygisk.so",
	"/debug_ramdisk",
	"/dev/zygisk"
};

static const char* const suspicious_mount_types[] = {
	"overlay"
};

static const char* const suspicious_mount_paths[] = {
	"/apex/com.android.art/bin/dex2oat",
	"/data/adb",
	"/data/app",
	"/system/apex/com.android.art/bin/dex2oat",
	"/system/etc/preloaded-classes",
	"/system/etc/hosts",
	"/dev/zygisk"
};

static const char* const suspicious_mount_devices[] = {
	"KSU"
};

static const char* const hidden_names[] = {
	"adb",
	"ksu",
	"magisk",
	"zygisk"
};

static uid_t getuid(void) {
	const struct cred* const credentials = current_cred();
	if (credentials == NULL) {
		return 0;
	}
	return credentials->uid.val;
}

void load_limitless_hide_config(void) {
	struct file *file;
	loff_t pos = 0;
	int bytes;
	mm_segment_t old_fs;

	memset(limitless_hide_buffer, 0, MAX_HIDE_SIZE);

	file = filp_open("/data/system/Limitless/hide-folder.txt", O_RDONLY, 0);
	if (IS_ERR(file)) {
		printk(KERN_INFO "next-hide: cant open hide-folder.txt, eror: %ld\n", PTR_ERR(file));
		return;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(file, limitless_hide_buffer, MAX_HIDE_SIZE - 1, &pos);
	set_fs(old_fs);
	filp_close(file, NULL);

	if (bytes > 0) {
		while (bytes > 0 && (limitless_hide_buffer[bytes - 1] == '\n' || limitless_hide_buffer[bytes - 1] == '\r')) {
			limitless_hide_buffer[bytes - 1] = '\0';
			bytes--;
		}
		printk(KERN_INFO "next-hide: Add list: %s\n", limitless_hide_buffer);
	}
}

static ssize_t next_hide_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
	load_limitless_hide_config();
	return count;
}

static const struct file_operations next_hide_fops = {
	.owner = THIS_MODULE,
	.write = next_hide_write,
};

int is_suspicious_path(const struct path* const file)
{
	size_t index = 0, size = 4096;
	int res = -1, status = 0;
	char *path = NULL, *ptr = NULL, *end = NULL;
	
	if (!uid_matches() || file == NULL) {
		status = 0;
		goto out;
	}
	
	path = kmalloc(size, GFP_KERNEL);
	if (path == NULL) {
		status = -1;
		goto out;
	}
	
	ptr = d_path(file, path, size);
	if (IS_ERR(ptr)) {
		status = -1;
		goto out;
	}
	
	end = mangle_path(path, ptr, " \t\n\\");
	if (!end) {
		status = -1;
		goto out;
	}
	
	res = end - path;
	path[(size_t) res] = '\0';
	
	for (index = 0; index < ARRAY_SIZE(suspicious_paths); index++) {
		const char* const name = suspicious_paths[index];
		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "next-hide: file access to '%s' denied for UID %i\n", name, getuid());
			status = 1;
			goto out;
		}
	}
	
out:
	kfree(path);
	return status;
}

int suspicious_path(const struct filename* const name)
{
	int status = 0, ret = 0;
	struct path path;
	
	if (IS_ERR(name)) {
		return -1;
	}
	if (!uid_matches() || name == NULL) {
		return 0;
	}
	
	ret = kern_path(name->name, LOOKUP_FOLLOW, &path);
	if (!ret) {
		status = is_suspicious_path(&path);
		path_put(&path);
	}
	return status;
}

int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root)
{
	size_t index = 0, size = 4096;
	int res = -1, status = 0;
	char* path = NULL, *ptr = NULL, *end = NULL;
	struct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };
	struct mount* real = real_mount(mnt);
	
	if (!uid_matches()) {
		status = 0;
		goto out;
	}
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_types); index++) {
		const char* const name = suspicious_mount_types[index];
		if (strcmp(mnt->mnt_root->d_sb->s_type->name, name) == 0) {
			status = 1;
			goto out;
		}
	}
	
	path = kmalloc(size, GFP_KERNEL);
	if (path == NULL) {
		status = -1;
		goto out;
	}
	
	ptr = __d_path(&mnt_path, root, path, size);
	if (!ptr) {
		status = -1;
		goto out;
	}
	
	end = mangle_path(path, ptr, " \t\n\\");
	if (!end) {
		status = -1;
		goto out;
	}
	
	res = end - path;
	path[(size_t) res] = '\0';
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_paths); index++) {
		const char* const name = suspicious_mount_paths[index];
		if (memcmp(path, name, strlen(name)) == 0) {
			status = 1;
			goto out;
		}
	}
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_devices); index++) {
		const char* const name = suspicious_mount_devices[index];
		if (real->mnt_devname != NULL && strcmp(real->mnt_devname, name) == 0) {
			status = 1;
			goto out;
		}
	}
	
out:
	kfree(path);
	return status;
}

int is_hidden_name(const char *name, int namlen)
{
	size_t index;

	if (name == NULL || namlen <= 0) {
		return 0;
	}

	if (uid_matches()) {
		for (index = 0; index < ARRAY_SIZE(hidden_names); index++) {
			if (strnstr(name, hidden_names[index], namlen) != NULL) {
				return 1;
			}
		}
	}

	if (strlen(limitless_hide_buffer) > 0) {
		if (strnstr(limitless_hide_buffer, name, strlen(limitless_hide_buffer)) != NULL) {
			return 1;
		}
	}

	return 0;
}

static int __init init_next_hide(void) {
	proc_create("next_hide_refresh", 0222, NULL, &next_hide_fops);
	return 0;
}
fs_initcall(init_next_hide);
