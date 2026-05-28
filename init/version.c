/*
 *  linux/init/version.c
 *
 *  Copyright (C) 1992  Theodore Ts'o
 *
 *  May be freely distributed as part of Linux.
 */

#include <generated/compile.h>
#include <linux/module.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include <linux/version.h>
#include <linux/proc_ns.h>

#ifndef CONFIG_KALLSYMS
#define version(a) Version_ ## a
#define version_string(a) version(a)

extern int version_string(LINUX_VERSION_CODE);
int version_string(LINUX_VERSION_CODE);
#endif

struct uts_namespace init_uts_ns = {
	.kref = KREF_INIT(2),
	.name = {
		.sysname	= UTS_SYSNAME,
		.nodename	= UTS_NODENAME,
		.release	= UTS_RELEASE,
		.version	= UTS_VERSION,
		.machine	= UTS_MACHINE,
		.domainname	= UTS_DOMAINNAME,
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_UTS_INIT_INO,
#ifdef CONFIG_UTS_NS
	.ns.ops = &utsns_operations,
#endif
};
EXPORT_SYMBOL_GPL(init_uts_ns);

/* FIXED STRINGS! Don't touch! */
const char linux_banner[] =
	"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
	LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";

#ifdef CONFIG_LIMITLESS
const char linux_proc_banner[] =
	"%s version %s (%s@%s) (%s) %s\n";
#else
const char linux_proc_banner[] =
	"%s version %s"
	" (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ")"
	" (" LINUX_COMPILER ") %s\n";
#endif

/* Limitless Identity */
#ifdef CONFIG_LIMITLESS
 char thre_kernel_name[64] = UTS_RELEASE;
 char thre_user_name[64]   = LINUX_COMPILE_BY;
 char thre_host_name[64]   = LINUX_COMPILE_HOST;
 char thre_compiler[128]   = LINUX_COMPILER;
 char thre_build_date[128] = UTS_VERSION;

static char default_kernel_name[64] = UTS_RELEASE;
static char default_user_name[64]   = LINUX_COMPILE_BY;
static char default_host_name[64]   = LINUX_COMPILE_HOST;
static char default_compiler[128]   = LINUX_COMPILER;
static char default_build_date[128] = UTS_VERSION;

module_param_string(default_kernel_name, default_kernel_name, sizeof(default_kernel_name), 0444);
module_param_string(default_user_name,   default_user_name,   sizeof(default_user_name),   0444);
module_param_string(default_host_name,   default_host_name,   sizeof(default_host_name),   0444);
module_param_string(default_compiler,    default_compiler,    sizeof(default_compiler),    0444);
module_param_string(default_build_date,  default_build_date,  sizeof(default_build_date),  0444);

EXPORT_SYMBOL_GPL(thre_kernel_name);
EXPORT_SYMBOL_GPL(thre_user_name);
EXPORT_SYMBOL_GPL(thre_host_name);
EXPORT_SYMBOL_GPL(thre_compiler);
EXPORT_SYMBOL_GPL(thre_build_date);

static int set_kernel_name(const char *val, const struct kernel_param *kp)
{
    char tmp[64];
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", val);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '\n')
        tmp[len - 1] = '\0';
    snprintf(thre_kernel_name, sizeof(thre_kernel_name), "%s", tmp);
    snprintf(init_uts_ns.name.release, sizeof(init_uts_ns.name.release), "%s", tmp);
    return 0;
}
static int set_user_name(const char *val, const struct kernel_param *kp)
{
    char tmp[64];
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", val);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '\n')
        tmp[len - 1] = '\0';
    
    snprintf(thre_user_name, sizeof(thre_user_name), "%s", tmp);
    /* init_uts_ns.name.sysname JANGAN DITIMPA agar tetap "Linux" */
    return 0;
}
static int set_host_name(const char *val, const struct kernel_param *kp)
{
    char tmp[64];
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", val);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '\n')
        tmp[len - 1] = '\0';

    snprintf(thre_host_name, sizeof(thre_host_name), "%s", tmp);
    /* Biarkan nodename asli jika ingin aman, atau timpa jika ingin 'uname -n' berubah */
    return 0;
}
static int set_compiler_name(const char *val, const struct kernel_param *kp)
{
    char tmp[128];
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", val);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '\n')
        tmp[len - 1] = '\0';

    snprintf(thre_compiler, sizeof(thre_compiler), "%s", tmp);
    return 0;
}
static int set_build_date(const char *val, const struct kernel_param *kp)
{
    char tmp[128];
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", val);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '\n')
        tmp[len - 1] = '\0';

    snprintf(thre_build_date, sizeof(thre_build_date), "%s", tmp);
    snprintf(init_uts_ns.name.version, sizeof(init_uts_ns.name.version), "%s", tmp);
    return 0;
}

static int param_get_thre_string(char *buffer, const struct kernel_param *kp)
{
    return scnprintf(buffer, PAGE_SIZE, "%s", (char *)kp->arg);
}

static const struct kernel_param_ops kernel_name_ops = { .set = set_kernel_name, .get = param_get_thre_string };
static const struct kernel_param_ops user_ops = { .set = set_user_name, .get = param_get_thre_string };
static const struct kernel_param_ops host_ops = { .set = set_host_name, .get = param_get_thre_string };
static const struct kernel_param_ops comp_ops = { .set = set_compiler_name, .get = param_get_thre_string };
static const struct kernel_param_ops date_ops = { .set = set_build_date, .get = param_get_thre_string };

module_param_cb(thre_kernel_name, &kernel_name_ops, thre_kernel_name, 0644);
module_param_cb(thre_user_name,   &user_ops,        thre_user_name,   0644);
module_param_cb(thre_host_name,   &host_ops,        thre_host_name,   0644);
module_param_cb(thre_compiler,    &comp_ops,        thre_compiler,    0644);
module_param_cb(thre_build_date,  &date_ops,        thre_build_date,  0644);
#endif
/* linex Project */