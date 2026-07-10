#include "selinux.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "objsec.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"

/*
 * Cached SID values for frequently checked contexts.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

#ifdef CONFIG_KSU_SUSFS
#define KERNEL_PRIV_APP_DOMAIN "u:r:priv_app:s0:c512,c768"

u32 susfs_ksu_sid = 0;
u32 susfs_init_sid = 0;
u32 susfs_zygote_sid = 0;
u32 susfs_priv_app_sid = 0;
#endif

static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    struct task_security_struct *tsec;
    u32 sid;
    int error;

    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }

    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain,
                sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
		if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 0)
bool __maybe_unused
is_ksu_transition(const struct task_security_struct *old_tsec,
		  const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid(KERNEL_SU_CONTEXT,
					 strlen(KERNEL_SU_CONTEXT), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred(void)
{
    if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred failed.\n");
    }
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	selinux_state.enforcing = enforce;
#else
	selinux_enforcing = enforce;
#endif
#endif
}

bool getenforce(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	if (selinux_state.disabled) {
		return false;
	}
#else
	if (selinux_disabled) {
		return false;
	}
#endif
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	return selinux_state.enforcing;
#else
	return selinux_enforcing;
#endif
#else
	return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

void cache_sid(void)
{
    int err;

    err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT),
                                   &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
#ifdef CONFIG_KSU_SUSFS
        susfs_ksu_sid = cached_su_sid;
#endif
    }

    err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT),
                                   &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
#ifdef CONFIG_KSU_SUSFS
        susfs_zygote_sid = cached_zygote_sid;
#endif
    }

    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT),
                                   &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
#ifdef CONFIG_KSU_SUSFS
        susfs_init_sid = cached_init_sid;
#endif
    }

    err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT),
                                   &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }

#ifdef CONFIG_KSU_SUSFS
    err = security_secctx_to_secid(KERNEL_PRIV_APP_DOMAIN, strlen(KERNEL_PRIV_APP_DOMAIN),
                                   &susfs_priv_app_sid);
    if (err) {
        pr_warn("Failed to cache susfs priv_app SID: %d\n", err);
        susfs_priv_app_sid = 0;
    } else {
        pr_info("Cached susfs priv_app SID: %u\n", susfs_priv_app_sid);
    }
#endif
}

static bool is_sid_match(const struct cred *cred, u32 cached_sid,
                         const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
    if (!tsec) {
        return false;
    }
    
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        abort_creds(cred);
        return;
    }
    commit_creds(cred);
}

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_sid_equal(const struct cred *cred, u32 sid2) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif

    if (!tsec) {
        return false;
    }
    return tsec->sid == sid2;
}

u32 susfs_get_sid_from_name(const char *secctx_name)
{
    u32 out_sid = 0;
    int err;
    
    if (!secctx_name) {
        pr_err("secctx_name is NULL\n");
        return 0;
    }
    err = security_secctx_to_secid(secctx_name, strlen(secctx_name),
                       &out_sid);
    if (err) {
        pr_err("failed getting sid from secctx_name: %s, err: %d\n", secctx_name, err);
        return 0;
    }
    return out_sid;
}

u32 susfs_get_current_sid(void) {
    return current_sid();
}

bool susfs_is_current_zygote_domain(void) {
    return unlikely(current_sid() == susfs_zygote_sid);
}

bool susfs_is_current_ksu_domain(void) {
    return unlikely(current_sid() == susfs_ksu_sid);
}

bool susfs_is_current_init_domain(void) {
    return unlikely(current_sid() == susfs_init_sid);
}

/* * Fungsi setter kosong (stub) di bawah ini dipertahankan demi menjaga 
 * kompatibilitas panggilan eksternal dari berkas luar KSU / SuSFS hook.
 */
void susfs_set_zygote_sid(void) {}
void susfs_set_ksu_sid(void) {}
void susfs_set_init_sid(void) {}
void susfs_set_priv_app_sid(void) {}
#endif // #ifdef CONFIG_KSU_SUSFS
