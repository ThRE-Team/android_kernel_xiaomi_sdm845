#ifndef _LINUX_NEXT_HIDE_H_
#define _LINUX_NEXT_HIDE_H_

#include <linux/fs.h>
#include <linux/mount.h>

#define getname_safe(name) (name == NULL ? ERR_PTR(-EINVAL) : getname(name))
#define putname_safe(name) (IS_ERR(name) ? NULL : putname(name))

#ifdef CONFIG_LIMITLESS

int is_suspicious_path(const struct path* const file);
int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root);
int suspicious_path(const struct filename* const name);
int is_hidden_name(const char *name, int namlen);

#else

static inline int is_suspicious_path(const struct path* const file) { return 0; }
static inline int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root) { return 0; }
static inline int suspicious_path(const struct filename* const name) { return 0; }
static inline int is_hidden_name(const char *name, int namlen) { return 0; }

#endif
#endif
