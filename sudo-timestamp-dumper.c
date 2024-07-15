#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

static uint8_t *slurp_file(const char *path, size_t *sz_ptr) {
    if (!path) {
        fprintf(stderr, "slurp_file provided with NULL path. WTF am I supposed to open!?\n");
        exit(2);
    }
    if (!sz_ptr) {
        fprintf(stderr,
                "slurp_file provided with NULL sz_ptr. You really probably want the size...\n");
        exit(3);
    }
    errno    = 0;
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        const int fopen_errno = errno;
        fprintf(stderr, "Couldn't open '%s' for slurping. errno: %d a.k.a. %s\n", path, fopen_errno,
                strerror(fopen_errno));
        exit(4);
    }
    errno                   = 0;
    const int fseek_end_res = fseek(fh, 0, SEEK_END);
    if (fseek_end_res) {
        const int fseek_end_errno = errno;
        fprintf(stderr, "Couldn't seek to end of '%s' for slurping. errno: %d a.k.a. %s\n", path,
                fseek_end_errno, strerror(fseek_end_errno));
        exit(5);
    }
    errno                = 0;
    const long ftell_res = ftell(fh);
    if (ftell_res < 0) {
        const int ftell_errno = errno;
        fprintf(stderr, "Couldn't ftell on '%s' for slurping. errno: %d a.k.a. %s\n", path,
                ftell_errno, strerror(ftell_errno));
        exit(6);
    }
    errno = 0;
    rewind(fh);
    const int rewind_errno = errno;
    if (rewind_errno) {
        fprintf(stderr, "Couldn't rewind on '%s' for slurping. errno: %d a.k.a. %s\n", path,
                rewind_errno, strerror(rewind_errno));
        exit(7);
    }
    const size_t sz = (size_t)ftell_res;
    errno           = 0;
    uint8_t *buf    = malloc(sz);
    if (!buf) {
        const int malloc_errno = errno;
        fprintf(stderr,
                "Couldn't malloc buffer of size %zu for '%s' for slurping. errno: %d a.k.a. %s\n",
                sz, path, malloc_errno, strerror(malloc_errno));
        exit(8);
    }
    errno                  = 0;
    const size_t fread_res = fread(buf, sz, 1, fh);
    if (fread_res != 1) {
        const int fread_errno  = errno;
        const char *feof_str   = feof(fh) ? "IS_EOF" : "NOT_EOF";
        const char *ferror_str = ferror(fh) ? "IS_FERROR" : "NO_FERROR";
        fprintf(stderr,
                "Couldn't read size %zu from '%s' for slurping. feof: %s ferror: %s errno: %d "
                "a.k.a. %s\n",
                sz, path, feof_str, ferror_str, fread_errno, strerror(fread_errno));
        free(buf);
        exit(9);
    }
    errno                = 0;
    const int fclose_res = fclose(fh);
    if (fclose_res) {
        const int fclose_errno = errno;
        const char *fclose_str = fclose_res ? "IS_EOF" : "IS_ZERO";
        fprintf(stderr,
                "Couldn't fclose(fh) of '%s' for slurping!? fclose res: %s errno: %d a.k.a. %s\n",
                path, fclose_str, fclose_errno, strerror(fclose_errno));
        free(buf);
        exit(10);
    }
    *sz_ptr = sz;
    return buf;
}

static void print_usage(void) {
    printf("Usage: %s <sudo timestamp DB file>\n", getprogname());
}

static bool check_access(const char *path) {
    errno         = 0;
    const int res = access(path, R_OK);
    return false;
}

static struct kinfo_proc *get_kinfo_proc(void) {
    pid_t pid                = getpid();
    struct kinfo_proc *kinfo = malloc(sizeof(struct kinfo_proc));
    int mib[]                = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    size_t len               = sizeof(struct kinfo_proc);
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), kinfo, &len, NULL, 0) != 0) {
        free(kinfo);
        fprintf(stderr, "Could not get kinfo_proc for self pid %d\n", (int)pid);
        return NULL;
    }
    return kinfo;
}

static void dump_kinfo_proc(void) {
    struct kinfo_proc *ki = get_kinfo_proc();
    if (!ki) {
        return;
    }
    printf("p_comm: \"%.*s\"\n", (int)sizeof(ki->kp_proc.p_comm), ki->kp_proc.p_comm);
    printf("e_paddr: %p\n", (void *)ki->kp_eproc.e_paddr);
    printf("e_sess: %p\n", (void *)ki->kp_eproc.e_sess);
    printf("e_pcred: p_refcnt: %d p_rgid: %d p_ruid: %d p_svgid: %d p_svuid: %d pc_ucred: %p\n",
           ki->kp_eproc.e_pcred.p_refcnt, ki->kp_eproc.e_pcred.p_rgid, ki->kp_eproc.e_pcred.p_ruid,
           ki->kp_eproc.e_pcred.p_svgid, ki->kp_eproc.e_pcred.p_svuid,
           (void *)ki->kp_eproc.e_pcred.pc_ucred);
    free(ki);
}

static void dump_env(const char *envp[]) {
    for (int i = 0; envp[i]; ++i) {
        printf("env[%3d]: %s\n", i, envp[i]);
    }
}

static bool get_sudo_uid(uid_t *puid) {
    const char *uid_str = NULL;
    if ((uid_str = getenv("SUDO_UID"))) {
        char *eptr             = NULL;
        errno                  = 0;
        unsigned long int uidl = strtoul(uid_str, &eptr, 10);
        if (errno) {
            fprintf(stderr, "get_sudo_uid(): strtoul() of SUDO_UID=%s failed with \"%s\"", uid_str,
                    strerror(errno));
            return false;
        }
        if (uidl > UID_MAX) {
            fprintf(stderr, "get_sudo_uid(): SUDO_UID=%s is greater than UID_MAX (a.k.a.) %lu",
                    uid_str, UID_MAX);
            return false;
        }
        if (!puid) {
            fprintf(stderr, "get_sudo_uid(): uid_t *puid is NULL!\n");
            return false;
        }
        *puid = (uid_t)uidl;
        return true;
    }
    return false;
}

static bool get_sudo_gid(gid_t *pgid) {
    const char *gid_str = NULL;
    if ((gid_str = getenv("SUDO_GID"))) {
        char *eptr             = NULL;
        errno                  = 0;
        unsigned long int gidl = strtoul(gid_str, &eptr, 10);
        if (errno) {
            fprintf(stderr, "get_sudo_gid(): strtoul() of SUDO_GID=%s failed with \"%s\"", gid_str,
                    strerror(errno));
            return false;
        }
        if (gidl > GID_MAX) {
            fprintf(stderr, "get_sudo_gid(): SUDO_GID=%s is greater than GID_MAX (a.k.a.) %lu",
                    gid_str, GID_MAX);
            return false;
        }
        if (!pgid) {
            fprintf(stderr, "get_sudo_gid(): gid_t *pgid is NULL!\n");
            return false;
        }
        *pgid = (gid_t)gidl;
        return true;
    }
    return false;
}

int main(int argc, const char *argv[], const char *envp[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }

    uid_t sudo_uid    = UID_MAX;
    gid_t sudo_gid    = GID_MAX;
    bool has_sudo_uid = false;
    bool has_sudo_gid = false;

    if ((has_sudo_uid = get_sudo_uid(&sudo_uid))) {
        printf("get_sudo_uid() => %5u\n", sudo_uid);
    } else {
        printf("get_sudo_uid() => %5s\n", "n/a");
    }
    if ((has_sudo_gid = get_sudo_gid(&sudo_gid))) {
        printf("get_sudo_gid() => %5u\n", sudo_gid);
    } else {
        printf("get_sudo_gid() => %5s\n", "n/a");
    }
    printf("getuid()       => %5u\n", getuid());
    printf("geteuid()      => %5u\n", geteuid());
    printf("getgid()       => %5u\n", getgid());
    printf("getegid()      => %5u\n", getegid());
    printf("getpgid()      => %5u\n", getpgid(getpid()));
    printf("getsid()       => %5u\n", getsid(getpid()));

    dump_kinfo_proc();

    // dump_env(envp);

    return 0;
}
