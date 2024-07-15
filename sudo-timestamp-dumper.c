#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof(((arr))[0]))

// Time stamp entry types
#define TS_GLOBAL 0x01   // not restricted by tty or ppid
#define TS_TTY 0x02      // restricted by tty
#define TS_PPID 0x03     // restricted by ppid
#define TS_LOCKEXCL 0x04 // special lock record
// Time stamp flags
#define TS_DISABLED 0x01 // entry disabled
#define TS_ANYUID 0x02   // ignore uid, only valid in key

struct timestamp_entry_header {
    uint16_t version; // version number
    uint16_t size;    // entry size
};
typedef struct timestamp_entry_header timestamp_entry_header_t;

struct timestamp_entry_v2 {
    timestamp_entry_header_t header; // version agnostic header
    uint16_t type;                   // TS_GLOBAL, TS_TTY, TS_PPID
    uint16_t flags;                  // TS_DISABLED, TS_ANYUID
    uid_t auth_uid;                  // uid to authenticate as
    pid_t sid;                       // session ID associated with tty/ppid
    struct timespec start_time;      // session/ppid start time
    struct timespec ts;              // time stamp (CLOCK_MONOTONIC)
    union {
        dev_t ttydev; // tty device number
        pid_t ppid;   // parent pid
    } u;
};
typedef struct timestamp_entry_v2 timestamp_entry_v2_t;

static uint8_t *slurp_file(const char *path, size_t *sz_ptr) {
    const int ret_base = 8;
    if (!path) {
        fprintf(stderr, "slurp_file provided with NULL path. WTF am I supposed to open!?\n");
        exit(ret_base + 1);
    }
    if (!sz_ptr) {
        fprintf(stderr,
                "slurp_file provided with NULL sz_ptr. You really probably want the size...\n");
        exit(ret_base + 2);
    }
    errno    = 0;
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        const int fopen_errno = errno;
        fprintf(stderr, "Couldn't open '%s' for slurping. errno: %d a.k.a. %s\n", path, fopen_errno,
                strerror(fopen_errno));
        exit(ret_base + 3);
    }
    errno                   = 0;
    const int fseek_end_res = fseek(fh, 0, SEEK_END);
    if (fseek_end_res) {
        const int fseek_end_errno = errno;
        fprintf(stderr, "Couldn't seek to end of '%s' for slurping. errno: %d a.k.a. %s\n", path,
                fseek_end_errno, strerror(fseek_end_errno));
        exit(ret_base + 4);
    }
    errno                = 0;
    const long ftell_res = ftell(fh);
    if (ftell_res < 0) {
        const int ftell_errno = errno;
        fprintf(stderr, "Couldn't ftell on '%s' for slurping. errno: %d a.k.a. %s\n", path,
                ftell_errno, strerror(ftell_errno));
        exit(ret_base + 5);
    }
    errno = 0;
    rewind(fh);
    const int rewind_errno = errno;
    if (rewind_errno) {
        fprintf(stderr, "Couldn't rewind on '%s' for slurping. errno: %d a.k.a. %s\n", path,
                rewind_errno, strerror(rewind_errno));
        exit(ret_base + 6);
    }
    const size_t sz = (size_t)ftell_res;
    errno           = 0;
    uint8_t *buf    = malloc(sz);
    if (!buf) {
        const int malloc_errno = errno;
        fprintf(stderr,
                "Couldn't malloc buffer of size %zu for '%s' for slurping. errno: %d a.k.a. %s\n",
                sz, path, malloc_errno, strerror(malloc_errno));
        exit(ret_base + 7);
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
        exit(ret_base + 8);
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
        exit(ret_base + 9);
    }
    *sz_ptr = sz;
    return buf;
}

static bool check_access(const char *path) {
    if (!path) {
        fprintf(stderr, "check_access(): path is NULL!\n");
        return false;
    }
    const size_t path_len = strlen(path);
    if (!path_len) {
        fprintf(stderr, "check_access(): path is empty string!\n");
        return false;
    }
    const bool is_abs = path[0] == '/';
    errno             = 0;
    const int root_fd = is_abs ? open("/", O_SEARCH) : -1;
    if (is_abs && root_fd < 0) {
        fprintf(stderr, "Can't open a file descriptor to \"/\"! errno => %d a.k.a. \"%s\"\n", errno,
                strerror(errno));
        return false;
    }
    errno         = 0;
    const int res = faccessat(is_abs ? root_fd : AT_FDCWD, path, R_OK, AT_EACCESS);
    if (res) {
        fprintf(stderr, "Can't read path \"%s\". errno => %d a.k.a. \"%s\"\n", path, errno,
                strerror(errno));
        return false;
    }
    return true;
}

static bool get_sudo_uid(uid_t *puid) {
    const char *uid_str = NULL;
    if ((uid_str = getenv("SUDO_UID"))) {
        char *eptr             = NULL;
        errno                  = 0;
        unsigned long int uidl = strtoul(uid_str, &eptr, 10);
        if (errno) {
            fprintf(stderr,
                    "get_sudo_uid(): strtoul() of SUDO_UID=%s failed with errno => %d a.k.a. "
                    "\"%s\"",
                    uid_str, errno, strerror(errno));
            return false;
        }
        if (uidl > UID_MAX) {
            fprintf(stderr, "get_sudo_uid(): SUDO_UID=%s is greater than UID_MAX a.k.a. %lu",
                    uid_str, (unsigned long int)UID_MAX);
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
            fprintf(stderr,
                    "get_sudo_gid(): strtoul() of SUDO_GID=%s failed with errno => %d \"%s\"",
                    gid_str, errno, strerror(errno));
            return false;
        }
        if (gidl > GID_MAX) {
            fprintf(stderr, "get_sudo_gid(): SUDO_GID=%s is greater than GID_MAX a.k.a. %lu",
                    gid_str, (unsigned long int)GID_MAX);
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

static void dump_timespec(const uint8_t *ts_buf, const size_t ts_buf_sz) {
    static const uint16_t v2_types[]    = {TS_GLOBAL, TS_TTY, TS_PPID, TS_LOCKEXCL};
    static const char *v2_type_names[]  = {"TS_GLOBAL", "TS_TTY", "TS_PPID", "TS_LOCKEXCL"};
    static const uint16_t v2_flags[]    = {TS_DISABLED, TS_ANYUID};
    static const char *v2_flag_names[]  = {"TS_DISABLED", "TS_ANYUID"};
    static uint16_t known_flags_bitmask = 0;
    if (!known_flags_bitmask) {
        for (size_t j = 0; j < ARRAY_SIZE(v2_flags); ++j) {
            known_flags_bitmask |= v2_flags[j];
        }
    }
    static size_t max_known_flag_idx = 0;
    if (!max_known_flag_idx) {
        max_known_flag_idx =
            sizeof(unsigned int) * CHAR_BIT - __builtin_clz(known_flags_bitmask) - 1;
    }

    size_t i                                   = 0;
    const timestamp_entry_header_t *const ehdr = (timestamp_entry_header_t *)(ts_buf + ts_buf_sz);
    for (const timestamp_entry_header_t *hdr = (timestamp_entry_header_t *)ts_buf; hdr < ehdr;
         hdr = (timestamp_entry_header_t *)((uintptr_t)hdr + hdr->size)) {
        printf("ts_entry[%3zu].version    => %hu\n", i, hdr->version);
        printf("ts_entry[%3zu].size       => 0x%hx\n", i, hdr->size);
        if (hdr->version == 2) {
            if (hdr->size != sizeof(timestamp_entry_v2_t)) {
                printf("ts_entry[%3zu] version 2 has bad header size 0x%hx, expected 0x%zx. "
                       "Skipping.\n",
                       i, hdr->size, sizeof(timestamp_entry_v2_t));
                continue;
            }
            const timestamp_entry_v2_t *tse = (timestamp_entry_v2_t *)hdr;

            const char *type_name = NULL;
            for (size_t j = 0; j < ARRAY_SIZE(v2_types); ++j) {
                if (tse->type == v2_types[j]) {
                    type_name = v2_type_names[j];
                    break;
                }
            }
            if (!type_name) {
                type_name = "UNKNOWN";
            }
            printf("ts_entry[%3zu].type       => %s (0x%hx)\n", i, type_name, tse->type);

            char flags_str[24]  = {'\0'};
            size_t max_flag_idx = 0;
            if (tse->flags) {
                max_flag_idx = sizeof(unsigned int) * CHAR_BIT - __builtin_clz(tse->flags) - 1;
            }
            const size_t flag_space_idx =
                max_known_flag_idx > max_flag_idx ? max_flag_idx : max_known_flag_idx;
            for (size_t j = 0; j < ARRAY_SIZE(v2_flags); ++j) {
                if (tse->flags & v2_flags[j]) {
                    strncat(flags_str, v2_flag_names[j], sizeof(flags_str) - 1 - strlen(flags_str));
                    if (j == flag_space_idx) {
                        strncat(flags_str, " ", sizeof(flags_str) - 1 - strlen(flags_str));
                    } else {
                        strncat(flags_str, ", ", sizeof(flags_str) - 1 - strlen(flags_str));
                    }
                }
            }
            const char *unknown_flags =
                (tse->flags & (uint16_t)~known_flags_bitmask) ? " (unknown flags detected)" : "";
            printf("ts_entry[%3zu].flags      => %s(0x%hx)%s\n", i, flags_str, tse->flags,
                   unknown_flags);

            printf("ts_entry[%3zu].auth_uid   => %u\n", i, tse->auth_uid);

            printf("ts_entry[%3zu].sid        => %d\n", i, tse->sid);

            struct tm stm      = {0};
            char tstr_buf[128] = {'\0'};
            errno              = 0;
            struct tm *rtm     = localtime_r(&tse->start_time.tv_sec, &stm);
            if (!rtm || errno) {
                fprintf(stderr,
                        "ts_entry[%3zu]: Couldn't convert start_time.tv_sec (%ld) to tm using "
                        "localtime_r. errno: %d a.k.a. \"%s\"\n",
                        i, tse->start_time.tv_sec, errno, strerror(errno));
            } else {
                errno = 0;
                strftime(tstr_buf, sizeof(tstr_buf) - 1, "%c", rtm);
                if (errno) {
                    fprintf(stderr,
                            "ts_entry[%3zu]: Couldn't strftime start_time.tv_sec (%ld). errno: %d "
                            "a.k.a. \"%s\"\n",
                            i, tse->start_time.tv_sec, errno, strerror(errno));
                } else {
                    printf("ts_entry[%3zu].start_time => %s\n", i, tstr_buf);
                }
            }
            errno = 0;
            memset(&stm, 0, sizeof(stm));
            rtm = NULL;
            rtm = localtime_r(&tse->ts.tv_sec, &stm);
            if (!rtm || errno) {
                fprintf(stderr,
                        "ts_entry[%3zu]: Couldn't convert ts.tv_sec (%ld) to tm using localtime_r. "
                        "errno: %d a.k.a. \"%s\"\n",
                        i, tse->ts.tv_sec, errno, strerror(errno));
            } else {
                memset(tstr_buf, '\0', sizeof(tstr_buf));
                errno = 0;
                strftime(tstr_buf, sizeof(tstr_buf) - 1, "%c", rtm);
                if (errno) {
                    fprintf(stderr,
                            "ts_entry[%3zu]: Couldn't strftime ts.tv_sec (%ld). errno: %d a.k.a. "
                            "\"%s\"\n",
                            i, tse->ts.tv_sec, errno, strerror(errno));
                } else {
                    printf("ts_entry[%3zu].ts         => %s\n", i, tstr_buf);
                }
            }

            if (tse->type == TS_TTY) {
                printf("ts_entry[%3zu].ttydev     => 0x08%x\n", i, tse->u.ttydev);
            } else if (tse->type == TS_PPID) {
                printf("ts_entry[%3zu].ppid       => %d\n", i, tse->u.ppid);
            }
        }
        if ((timestamp_entry_header_t *)((uintptr_t)hdr + hdr->size) < ehdr) {
            puts("");
        }
        ++i;
    }
}

static void print_usage(void) {
    printf("Usage: %s <sudo timestamp DB file>\n", getprogname());
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }
    const char *const ts_db_path = argv[1];

    uid_t sudo_uid          = UID_MAX;
    gid_t sudo_gid          = GID_MAX;
    const uid_t uid         = getuid();
    const uid_t euid        = geteuid();
    const gid_t gid         = getgid();
    const gid_t egid        = getegid();
    const bool has_sudo_uid = get_sudo_uid(&sudo_uid);
    const bool has_sudo_gid = get_sudo_gid(&sudo_gid);

    const bool can_read = check_access(ts_db_path);

    if (!can_read) {
        fprintf(stderr, "Aborting because the timestamp DB at \"%s\" can't be read!\n", ts_db_path);
        return 2;
    }

    size_t ts_buf_sz      = SIZE_T_MAX;
    const uint8_t *ts_buf = slurp_file(ts_db_path, &ts_buf_sz);
    if (!ts_buf || ts_buf_sz == SIZE_T_MAX) {
        fprintf(stderr, "Aborting because the timestamp DB at \"%s\" couldn't be slurped!\n",
                ts_db_path);
        return 3;
    }

    // drop privs now that the buffer is read
    uid_t max_uid = 0;
    if (has_sudo_uid && sudo_uid > max_uid) {
        max_uid = sudo_uid;
    }
    if (uid > max_uid) {
        max_uid = uid;
    }

    gid_t max_gid = 0;
    if (has_sudo_gid && sudo_gid > max_gid) {
        max_gid = sudo_gid;
    }
    if (gid > max_gid) {
        max_gid = gid;
    }

    assert(max_uid >= uid);
    assert(max_uid >= euid);
    assert(max_gid >= gid);
    assert(max_gid >= egid);

    errno                 = 0;
    const int set_gid_res = setgid(max_gid);
    if (set_gid_res) {
        fprintf(stderr,
                "Aborting - failed to drop privileges with setgid(%u). errno => %d a.k.a \"%s\"\n",
                max_gid, errno, strerror(errno));
        return 5;
    }
    errno                  = 0;
    const int set_egid_res = setegid(max_gid);
    if (set_egid_res) {
        fprintf(stderr,
                "Aborting - failed to drop privileges with setegid(%u). errno => %d a.k.a \"%s\"\n",
                max_gid, errno, strerror(errno));
        return 6;
    }

    errno                 = 0;
    const int set_uid_res = setuid(max_uid);
    if (set_uid_res) {
        fprintf(stderr,
                "Aborting - failed to drop privileges with setuid(%u). errno => %d a.k.a \"%s\"\n",
                max_uid, errno, strerror(errno));
        return 7;
    }
    errno                  = 0;
    const int set_euid_res = seteuid(max_uid);
    if (set_euid_res) {
        fprintf(stderr,
                "Aborting - failed to drop privileges with seteuid(%u). errno => %d a.k.a \"%s\"\n",
                max_uid, errno, strerror(errno));
        return 8;
    }

    dump_timespec(ts_buf, ts_buf_sz);

    free((uint8_t *)ts_buf);

    return 0;
}
