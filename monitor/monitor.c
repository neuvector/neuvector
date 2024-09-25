#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define DEBUG_FILE "/var/log/ranger/monitor.log"

//#define ENV_CLUSTER_BOOTSTRAP  "CLUSTER_BOOTSTRAP"
#define ENV_CLUSTER_JOIN       "CLUSTER_JOIN_ADDR"
#define ENV_CLUSTER_JOIN_PORT  "CLUSTER_JOIN_PORT"
#define ENV_CLUSTER_ADVERTISE  "CLUSTER_ADVERTISED_ADDR"
#define ENV_CLUSTER_ADV_PORT   "CLUSTER_ADVERTISED_PORT"
#define ENV_CLUSTER_BIND       "CLUSTER_BIND_ADDR"
#define ENV_CLUSTER_RPC_PORT   "CLUSTER_RPC_PORT"
#define ENV_CLUSTER_LAN_PORT   "CLUSTER_LAN_PORT"
#define ENV_CNET_TYPE          "CONTAINER_NET_TYPE"
#define ENV_ENFORCER_GRPC_PORT "ENFORCER_GRPC_PORT"
#define ENV_CTRL_SERVER_PORT   "CTRL_SERVER_PORT"
#define ENV_FED_SERVER_PORT    "FED_SERVER_PORT"
#define ENV_CTRL_PATH_DEBUG    "CTRL_PATH_DEBUG"
#define ENV_CTRL_SEARCH_REGS   "CTRL_SEARCH_REGISTRIES"
#define ENV_CTRL_NOT_RM_NSGRPS "CTRL_NOT_PRUNE_NSGROUPS"
#define ENV_CTRL_EN_ICMP_POL   "CTRL_EN_ICMP_POLICY"
#define ENV_DEBUG_LEVEL        "DEBUG_LEVEL"
#define ENV_TAP_INTERFACE      "TAP_INTERFACE"
#define ENV_TAP_ALL_CONTAINERS "TAP_ALL_CONTAINERS"
#define ENV_DOCKER_URL         "DOCKER_URL"
//#define ENV_STORE_KAFKA        "STORE_KAFKA_ADVERTISED_ADDR"
#define ENV_INTERNAL_SUBNETS   "CTRL_INTERNAL_SUBNETS"
#define ENV_PERSIST_CONFIG     "CTRL_PERSIST_CONFIG"
#define ENV_ADMISSION_PORT     "CTRL_ADMISSION_PORT"
#define ENV_SKIP_NV_PROTECT    "ENFORCER_SKIP_NV_PROTECT"
#define ENV_SHOW_MONITOR_TRACE "ENF_MONITOR_TRACE"
#define ENV_NO_KV_CONGEST_CTL  "ENF_NO_KV_CONGESTCTL"
#define ENV_NO_SCAN_SECRETS    "ENF_NO_SECRET_SCANS"
#define ENV_NO_AUTO_BENCHMARK  "ENF_NO_AUTO_BENCHMARK"
#define ENV_NO_SYSTEM_PROTECT  "ENF_NO_SYSTEM_PROFILES"
#define ENV_POLICY_PULLER      "ENF_NETPOLICY_PULL_INTERVAL"
#define ENV_PWD_VALID_UNIT     "PWD_VALID_UNIT"
#define ENV_RANCHER_EP         "RANCHER_EP"
#define ENV_RANCHER_SSO        "RANCHER_SSO"
#define ENV_TELE_NEUVECTOR_EP  "TELEMETRY_NEUVECTOR_EP"
#define ENV_TELE_CURRENT_VER   "TELEMETRY_CURRENT_VER"
#define ENV_TELEMETRY_FREQ     "TELEMETRY_FREQ"
#define ENV_NO_DEFAULT_ADMIN   "NO_DEFAULT_ADMIN"
#define ENV_CSP_ENV            "CSP_ENV"
#define ENV_CSP_PAUSE_INTERVAL "CSP_PAUSE_INTERVAL"
#define ENV_AUTOPROFILE_CLT    "AUTO_PROFILE_COLLECT"
#define ENV_SET_CUSTOM_BENCH   "CUSTOM_CHECK_CONTROL"

#define ENV_SCANNER_DOCKER_URL  "SCANNER_DOCKER_URL"
#define ENV_SCANNER_LICENSE     "SCANNER_LICENSE"
#define ENV_SCANNER_ON_DEMAND   "SCANNER_ON_DEMAND"
#define ENV_SCANNER_REGISTRY    "SCANNER_REGISTRY"
#define ENV_SCANNER_REPOSITORY  "SCANNER_REPOSITORY"
#define ENV_SCANNER_TAG         "SCANNER_TAG"
#define ENV_SCANNER_REG_USER    "SCANNER_REGISTRY_USERNAME"
#define ENV_SCANNER_REG_PASS    "SCANNER_REGISTRY_PASSWORD"
#define ENV_SCANNER_SCAN_LAYERS "SCANNER_SCAN_LAYERS"
#define ENV_SCANNER_BASE_IMAGE  "SCANNER_BASE_IMAGE"
#define ENV_SCANNER_CTRL_USER   "SCANNER_CTRL_API_USERNAME"
#define ENV_SCANNER_CTRL_PASS   "SCANNER_CTRL_API_PASSWORD"

#define ENV_THRT_SSL_TLS_1DOT0  "THRT_SSL_TLS_1DOT0"
#define ENV_THRT_SSL_TLS_1DOT1  "THRT_SSL_TLS_1DOT1"

#define DP_MISS_HB_MAX 60
#define PROC_EXIT_LIMIT  10

enum {
    PROC_CTRL = 0,
    PROC_SCANNER,
    PROC_DP,
    PROC_AGENT,
    PROC_SCANNER_STANDALONE,
    PROC_CTRL_OPA,
    PROC_MAX,
};

enum {
    MODE_CTRL = 0,
    MODE_AGENT,
    MODE_CTRL_AGENT,
    MODE_SCANNER,
};

#define PROC_ARGS_MAX 32

typedef struct proc_info_ {
    char name[32];
    char path[64];
    int active  : 1,
        running : 1;
    pid_t pid;
    struct timeval start;
    int exit_count;
    int exit_status;
} proc_info_t;

#define SCRIPT_SYSCTL   "sysctl -p"
#define SCRIPT_CONFIG   "/usr/local/bin/scripts/configure.sh"
#define SCRIPT_TEARDOWN "/usr/local/bin/scripts/teardown.sh"
//#define SCRIPT_KILL_CONSUL "kill $(pgrep consul)"
#define SCRIPT_KILL_CONSUL "consul leave"

// Must be same as in configure.sh. rc < 0 to indicate error.
#define RC_CONFIG_TC  0
#define RC_CONFIG_NOTC 1
#define RC_CONFIG_OVS 2

static proc_info_t g_procs[PROC_MAX] = {
[PROC_CTRL]                {"ctrl", "/usr/local/bin/controller", },
[PROC_SCANNER]             {"scanner", "/usr/local/bin/scanner", },
[PROC_DP]                  {"dp", "/usr/local/bin/dp", },
[PROC_AGENT]               {"agent", "/usr/local/bin/agent", },
[PROC_SCANNER_STANDALONE]  {"scanner", "/usr/local/bin/scanner", },
[PROC_CTRL_OPA]            {"opa", "/usr/local/bin/opa", },
};

static uint32_t g_dp_last_hb[MAX_DP_THREADS], g_dp_miss_hb[MAX_DP_THREADS];
static dp_mnt_shm_t *g_shm;
static int g_mode = MODE_CTRL;
static int g_pipe_driver = RC_CONFIG_TC;
static volatile sig_atomic_t g_exit_signal = 0;
static int g_exit_monitor_on_proc_exit = 0;
static int g_debugOpa = 0;

static void debug_ts(FILE *logfp)
{
    struct timeval now;
    struct tm *tm;

    gettimeofday(&now, NULL);
    tm = localtime(&now.tv_sec);

    fprintf(logfp, "%04d-%02d-%02dT%02d:%02d:%02d|MON|",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void debug(const char *fmt, ...)
{
    static FILE *logfp = NULL;
    va_list args;

/*
    if (logfp == NULL) {
        logfp = fopen(DEBUG_FILE, "a");

        if (logfp == NULL) {
            return;
        }
    }
*/
    logfp = stdout;

    debug_ts(logfp);
    va_start(args, fmt);
    vfprintf(logfp, fmt, args);
    va_end(args);
    fflush(logfp);
}

static void *create_shm(size_t size)
{
    int fd;
    void *ptr;

    fd = shm_open(DP_MNT_SHM_NAME, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return NULL;
    }

    if (ftruncate(fd, size) != 0) {
        close(fd);
        return NULL;
    }

    ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == NULL) {
        close(fd);
        return NULL;
    }

    close(fd);

    return ptr;
}

static int checkImplicitEnableFlag(char *enable)
{
    if (enable == NULL) return 0;
    if (enable[0] == '\0') return 1; // If the command line only has the option without value, consider it as enabled
    if (enable[0] == '1' || enable[0] == 'e' || // 'e' for enable
        enable[0] == 'y' || enable[0] == 'Y' || enable[0] == 't' || enable[0] == 'T') return 1;
    return 0;
}

static void getLogLevel(char **logLevel) {
    if ((strcmp(*logLevel, "error") == 0) ||
        (strcmp(*logLevel, "warn") == 0) ||
        (strcmp(*logLevel, "info") == 0) ||
        (strcmp(*logLevel, "debug") == 0)) {
        return;
    } else {
        if (checkImplicitEnableFlag(*logLevel) == 1) {
            *logLevel = "debug";
        } else {
            *logLevel = "info";
        }
    }
}

static pid_t fork_exec(int i)
{
    pid_t pid;
    char *args[PROC_ARGS_MAX], *join, *adv, *bind, *url, *iface, *subnets, *cnet_type;
    char *lan_port, *rpc_port, *grpc_port, *fed_port, *server_port, *join_port, *adv_port, *adm_port;
    char *license, *registry, *repository, *tag, *user, *pass, *base, *api_user, *api_pass, *enable;
    char *on_demand, *pwd_valid_unit, *rancher_ep, *debug_level, *policy_pull_period, *search_regs;
    char *telemetry_neuvector_ep, *telemetry_current_ver, *telemetry_freq, *csp_env, *csp_pause_interval;
    char *custom_check_control, *log_level;
    int a;

    switch (i) {
    case PROC_DP:
        // TODO: Here we set dp thread number to 1
        args[0] = g_procs[i].path;
        a = 1;
        args[a ++] = "-n";
        args[a ++] = "1";
        if ((iface = getenv(ENV_TAP_INTERFACE)) != NULL) {
            args[a ++] = "-i";
            args[a ++] = iface;
        }
        if (g_pipe_driver == RC_CONFIG_NOTC) {
            args[a ++] = "-c";
        }
        if ((enable = getenv(ENV_THRT_SSL_TLS_1DOT0)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-v";
                args[a ++] = "thrt_tls_1dot0";
            }
        }
        if ((enable = getenv(ENV_THRT_SSL_TLS_1DOT1)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-v";
                args[a ++] = "thrt_tls_1dot1";
            }
        }
        args[a] = NULL;
        break;
    case PROC_SCANNER:
        args[0] = g_procs[i].path;
        a = 1;
        args[a ++] = "-d";
        args[a ++] = "/etc/neuvector/db/";
        if ((url = getenv(ENV_SCANNER_DOCKER_URL)) != NULL) {
            args[a ++] = "-u";
            args[a ++] = url;
        }
        args[a] = NULL;
        break;
    case PROC_SCANNER_STANDALONE:
        args[0] = g_procs[i].path;
        a = 1;
        args[a ++] = "-d";
        args[a ++] = "/etc/neuvector/db/";
        if ((url = getenv(ENV_SCANNER_DOCKER_URL)) != NULL) {
            args[a ++] = "-u";
            args[a ++] = url;
        }
        if ((join = getenv(ENV_CLUSTER_JOIN)) != NULL) {
            args[a ++] = "-j";
            args[a ++] = join;
        }
        if ((join_port = getenv(ENV_CLUSTER_JOIN_PORT)) != NULL) {
            args[a ++] = "--join_port";
            args[a ++] = join_port;
        }
        if ((adv = getenv(ENV_CLUSTER_ADVERTISE)) != NULL) {
            args[a ++] = "-a";
            args[a ++] = adv;
        }
        if ((adv_port = getenv(ENV_CLUSTER_ADV_PORT)) != NULL) {
            args[a ++] = "--adv_port";
            args[a ++] = adv_port;
        }
        if (((license = getenv(ENV_SCANNER_LICENSE)) != NULL) || (on_demand = getenv(ENV_SCANNER_ON_DEMAND)) != NULL) {
            args[a ++] = "--license";
            args[a++] = "on_demand";

            g_exit_monitor_on_proc_exit = 1;
        }
        if ((registry = getenv(ENV_SCANNER_REGISTRY)) != NULL) {
            args[a ++] = "--registry";
            args[a ++] = registry;
        }
        if ((repository = getenv(ENV_SCANNER_REPOSITORY)) != NULL) {
            args[a ++] = "--repository";
            args[a ++] = repository;
        }
        if ((tag = getenv(ENV_SCANNER_TAG)) != NULL) {
            args[a ++] = "--tag";
            args[a ++] = tag;
        }
        if ((user = getenv(ENV_SCANNER_REG_USER)) != NULL) {
            args[a ++] = "--registry_username";
            args[a ++] = user;
        }
        if ((pass = getenv(ENV_SCANNER_REG_PASS)) != NULL) {
            args[a ++] = "--registry_password";
            args[a ++] = pass;
        }
        if ((base = getenv(ENV_SCANNER_BASE_IMAGE)) != NULL) {
            args[a ++] = "--base_image";
            args[a ++] = base;
        }
        if ((enable = getenv(ENV_SCANNER_SCAN_LAYERS)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "--scan_layers";
            }
        }
        if ((api_user = getenv(ENV_SCANNER_CTRL_USER)) != NULL) {
            args[a ++] = "--ctrl_username";
            args[a ++] = api_user;
        }
        if ((api_pass = getenv(ENV_SCANNER_CTRL_PASS)) != NULL) {
            args[a ++] = "--ctrl_password";
            args[a ++] = api_pass;
        }
        args[a] = NULL;
        break;
    case PROC_CTRL:
        args[0] = g_procs[i].path;
        a = 1;
/*
        if (getenv(ENV_CLUSTER_BOOTSTRAP)) {
            args[a ++] = "-b";
        }
*/
        if ((log_level = getenv(ENV_CTRL_PATH_DEBUG)) != NULL) {
            getLogLevel(&log_level);
            if (strcmp(log_level, "debug") == 0) {
                g_debugOpa = 1;
            }
            args[a ++] = "-log_level";
            args[a ++] = log_level;
        }
        if ((debug_level = getenv(ENV_DEBUG_LEVEL)) != NULL) {
            args[a ++] = "-v";
            args[a ++] = debug_level;
        }
        if ((search_regs = getenv(ENV_CTRL_SEARCH_REGS)) != NULL) {
            args[a ++] = "-search_registries";
            args[a ++] = search_regs;
        }
        if ((join = getenv(ENV_CLUSTER_JOIN)) != NULL) {
            args[a ++] = "-j";
            args[a ++] = join;
        }
        if ((adv = getenv(ENV_CLUSTER_ADVERTISE)) != NULL) {
            args[a ++] = "-a";
            args[a ++] = adv;
        }
        if ((bind = getenv(ENV_CLUSTER_BIND)) != NULL) {
            args[a ++] = "-b";
            args[a ++] = bind;
        }
        if ((server_port = getenv(ENV_CTRL_SERVER_PORT)) != NULL) {
            args[a ++] = "-p";
            args[a ++] = server_port;
        }
        if ((rpc_port = getenv(ENV_CLUSTER_RPC_PORT)) != NULL) {
            args[a ++] = "--rpc_port";
            args[a ++] = rpc_port;
        }
        if ((lan_port = getenv(ENV_CLUSTER_LAN_PORT)) != NULL) {
            args[a ++] = "--lan_port";
            args[a ++] = lan_port;
        }
        if ((url = getenv(ENV_DOCKER_URL)) != NULL) {
            args[a ++] = "-u";
            args[a ++] = url;
        }
        if ((subnets = getenv(ENV_INTERNAL_SUBNETS)) != NULL) {
            args[a ++] = "-n";
            args[a ++] = subnets;
        }
        if ((enable = getenv(ENV_PERSIST_CONFIG)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-pc";
            }
        }
        if ((adm_port = getenv(ENV_ADMISSION_PORT)) != NULL) {
            args[a ++] = "-admctrl_port";
            args[a ++] = adm_port;
        }
        if ((fed_port = getenv(ENV_FED_SERVER_PORT)) != NULL) {
            args[a ++] = "-fed_port";
            args[a ++] = fed_port;
        }
        if ((pwd_valid_unit = getenv(ENV_PWD_VALID_UNIT)) != NULL) {
            args[a ++] = "-pwd_valid_unit";
            args[a ++] = pwd_valid_unit;
        }
        if ((rancher_ep = getenv(ENV_RANCHER_EP)) != NULL) {
            args[a ++] = "-rancher_ep";
            args[a ++] = rancher_ep;
        }
        if ((enable = getenv(ENV_RANCHER_SSO)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-rancher_sso";
            }
        }
        if ((telemetry_neuvector_ep = getenv(ENV_TELE_NEUVECTOR_EP)) != NULL) {
            args[a++] = "-telemetry_neuvector_ep";
            args[a++] = telemetry_neuvector_ep;
        }
        if ((telemetry_current_ver = getenv(ENV_TELE_CURRENT_VER)) != NULL) {
            args[a++] = "-telemetry_current_ver";
            args[a++] = telemetry_current_ver;
        }
        if ((telemetry_freq = getenv(ENV_TELEMETRY_FREQ)) != NULL) {
            args[a++] = "-telemetry_freq";
            args[a++] = telemetry_freq;
        }
        if ((enable = getenv(ENV_NO_DEFAULT_ADMIN)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-no_def_admin";
            }
        }
        if ((enable = getenv(ENV_CTRL_NOT_RM_NSGRPS)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-no_rm_nsgroups";
            }
        }
        if ((enable = getenv(ENV_CTRL_EN_ICMP_POL)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "-en_icmp_policy";
            }
        }
        if ((csp_env = getenv(ENV_CSP_ENV)) != NULL) {
            args[a++] = "-csp_env";
            args[a++] = csp_env;
        }
        if ((csp_pause_interval = getenv(ENV_CSP_PAUSE_INTERVAL)) != NULL) {
            args[a++] = "-csp_pause_interval";
            args[a++] = csp_pause_interval;
        }
        if ((enable = getenv(ENV_AUTOPROFILE_CLT)) != NULL) {
            args[a++] = "-apc";
            args[a++] = enable;
        }
        if ((custom_check_control = getenv(ENV_SET_CUSTOM_BENCH)) != NULL) {
            args[a++] = "-cbench";
            args[a++] = custom_check_control;
        }
        args[a] = NULL;
        break;
    case PROC_AGENT:
        args[0] = g_procs[i].path;
        if (g_mode == MODE_CTRL_AGENT) {
            args[1] = "-c";
            a = 2;
        } else {
            a = 1;
            if ((join = getenv(ENV_CLUSTER_JOIN)) != NULL) {
                args[a ++] = "-j";
                args[a ++] = join;
            }
            if ((adv = getenv(ENV_CLUSTER_ADVERTISE)) != NULL) {
                args[a ++] = "-a";
                args[a ++] = adv;
            }
            if ((bind = getenv(ENV_CLUSTER_BIND)) != NULL) {
                args[a ++] = "-b";
                args[a ++] = bind;
            }
            if ((lan_port = getenv(ENV_CLUSTER_LAN_PORT)) != NULL) {
                args[a ++] = "--lan_port";
                args[a ++] = lan_port;
            }
            if ((grpc_port = getenv(ENV_ENFORCER_GRPC_PORT)) != NULL) {
                args[a ++] = "--grpc_port";
                args[a ++] = grpc_port;
            }
        }
        if (g_pipe_driver == RC_CONFIG_OVS) {
                args[a ++] = "-p";
                args[a ++] = "ovs";
        } else if (g_pipe_driver == RC_CONFIG_NOTC) {
                args[a ++] = "-p";
                args[a ++] = "no_tc";
        }
        if (getenv(ENV_TAP_ALL_CONTAINERS)) {
            args[a ++] = "-t";
        }
        if ((url = getenv(ENV_DOCKER_URL)) != NULL) {
            args[a ++] = "-u";
            args[a ++] = url;
        }
        if ((log_level = getenv(ENV_CTRL_PATH_DEBUG)) != NULL) {
            getLogLevel(&log_level);
            args[a ++] = "-log_level";
            args[a ++] = log_level;
        }
        if ((debug_level = getenv(ENV_DEBUG_LEVEL)) != NULL) {
            args[a ++] = "-v";
            args[a ++] = debug_level;
        }
        if ((cnet_type = getenv(ENV_CNET_TYPE)) != NULL) {
            args[a ++] = "-n";
            args[a ++] = cnet_type;
        }
        if (getenv(ENV_SKIP_NV_PROTECT)) {
            args[a ++] = "-s";
        }
        if (getenv(ENV_SHOW_MONITOR_TRACE)) {
            args[a ++] = "-m";      // show process monitor messages
        }
        if (getenv(ENV_NO_KV_CONGEST_CTL)) {
            args[a ++] = "-no_kvc";
        }
        if (getenv(ENV_NO_SCAN_SECRETS)) {
            args[a ++] = "-no_scrt";
        }
        if (getenv(ENV_NO_AUTO_BENCHMARK)) {
            args[a ++] = "-no_auto_benchmark";
        }
        if (getenv(ENV_NO_SYSTEM_PROTECT)) {
            args[a ++] = "-no_sys_protect";
        }
        if ((policy_pull_period = getenv(ENV_POLICY_PULLER)) != NULL) {
            args[a ++] = "-policy_puller";
            args[a ++] = policy_pull_period;
        }
        if ((enable = getenv(ENV_AUTOPROFILE_CLT)) != NULL) {
            args[a++] = "-apc";
            args[a++] = enable;
        }
        if ((custom_check_control = getenv(ENV_SET_CUSTOM_BENCH)) != NULL) {
            args[a++] = "-cbench";
            args[a++] = custom_check_control;
        }
        args[a] = NULL;
        break;

    case PROC_CTRL_OPA:
        args[0] = g_procs[i].path;
        a = 1;

        args[a ++] = "run";
        args[a ++] = "--server";
        args[a ++] = "--ignore=.*";
        if (g_debugOpa == 0) {
            args[a ++] = "--addr=127.0.0.1:8181";
        } else {
            args[a ++] = "--addr=:8181";
        }
        args[a ++] = "--log-level=error";
        args[a] = NULL;
        break;
    default:
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        return pid;
    }

    if (pid == 0) {
        // child : set the process group ID
        setpgrp();
        execv(args[0], args);
        exit(0);
    }
    return pid;
}

static void start_proc(int i)
{
    pid_t pid;

    if (g_procs[i].pid > 0) {
        return;
    }

    pid = fork_exec(i);
    if (pid > 0) {
        g_procs[i].pid = pid;
        g_procs[i].running = true;
        debug("Start %s, pid=%d\n", g_procs[i].name, g_procs[i].pid);
        gettimeofday(&g_procs[i].start, NULL);
    }
}

static void stop_proc(int i, int sig, int wait)
{
    if (g_procs[i].pid > 0) {
        debug("Kill %s with signal %d, pid=%d\n", g_procs[i].name, sig, g_procs[i].pid);
        kill(g_procs[i].pid, sig);

        int pid, status;
        while (wait) {
            pid = waitpid(WAIT_ANY, &status, WNOHANG);
            if (pid == g_procs[i].pid) {
                g_procs[i].running = false;
                g_procs[i].pid = 0;
                debug("%s stopped.\n", g_procs[i].name);
                break;
            }
        }
    }
}

#define SH_LINE_MAX 1024
#define SCRIPT_MAX  256
#define DEFAULT_RPC_PORT "18300"
#define DEFAULT_LAN_PORT "18301"

static int check_consul_ports(void)
{
    FILE *fp;
    char pline[SH_LINE_MAX];
    char shbuf[SCRIPT_MAX];
    char *rpc_port;
    char *lan_port;

    rpc_port = getenv(ENV_CLUSTER_RPC_PORT);
    lan_port = getenv(ENV_CLUSTER_LAN_PORT);

    if (rpc_port == NULL) {
        rpc_port = DEFAULT_RPC_PORT;
    }
    if (lan_port == NULL) {
        lan_port = DEFAULT_LAN_PORT;
    }
    sprintf(shbuf,"ss -lnp|grep '%s\\|%s'",rpc_port, lan_port);

    fp = popen(shbuf, "r");
    if (fp == NULL) {
        debug("Failed to run script\n");
        return 0;
    }

    int ret;
    //check open ports
    while (fgets(pline, sizeof(pline)-1, fp) != NULL) {
        if (strstr(pline, rpc_port) != NULL) {
            ret = system(SCRIPT_KILL_CONSUL);
            debug("consul rpc port is still open, command return = %d\n", ret);
            pclose(fp);
            return -1;
        }
        if (strstr(pline, lan_port) != NULL) {
            ret = system(SCRIPT_KILL_CONSUL);
            debug("consul lan port is still open, command return = %d\n", ret);
            pclose(fp);
            return -1;
        }
    }

    pclose(fp);
    return 0;
}

#define MAX_WAIT_TIME    60
static void wait_consul_exist()
{
    int i;
    for (i=0; i < MAX_WAIT_TIME; i++) {
        if (check_consul_ports() == 0) {
            break;
        }
        sleep(1);
    }
}

static void stop_related_proc(int cause)
{
    switch (cause) {
    case PROC_AGENT:
        stop_proc(PROC_DP, SIGTERM, false);
        if (g_mode == MODE_AGENT) {
            wait_consul_exist();
        }
        break;
    case PROC_CTRL:
        if (g_mode == MODE_CTRL_AGENT) {
            stop_proc(PROC_AGENT, SIGTERM, false);
            // dp will be restarted when recovering agent
            // stop_proc(PROC_DP, SIGTERM, false);
        }
        stop_proc(PROC_SCANNER, SIGTERM, false);
        wait_consul_exist();
        break;
    }
}

static void exit_handler(int sig)
{
    g_exit_signal = 1;
}

static int exit_monitor(void)
{
    int ret = 0;

    g_procs[PROC_CTRL].active = false;
    g_procs[PROC_SCANNER].active = false;
    g_procs[PROC_DP].active = false;
    g_procs[PROC_AGENT].active = false;
    g_procs[PROC_SCANNER_STANDALONE].active = false;

    signal(SIGCHLD, SIG_DFL);

    switch (g_mode) {
    case MODE_CTRL:
        stop_proc(PROC_CTRL, SIGTERM, true);
        // disable scanner in controller
        // stop_proc(PROC_SCANNER, SIGTERM, true);
        ret = system(SCRIPT_TEARDOWN);
        break;
    case MODE_AGENT:
        stop_proc(PROC_AGENT, SIGTERM, true);
        stop_proc(PROC_DP, SIGTERM, false);
        ret = system(SCRIPT_TEARDOWN);
        break;
    case MODE_CTRL_AGENT:
        stop_proc(PROC_AGENT, SIGTERM, true);
        stop_proc(PROC_DP, SIGTERM, false);
        stop_proc(PROC_CTRL, SIGTERM, true);
        // disable scanner in controller
        // stop_proc(PROC_SCANNER, SIGTERM, true);
        ret = system(SCRIPT_TEARDOWN);
        break;
    case MODE_SCANNER:
        stop_proc(PROC_SCANNER_STANDALONE, SIGTERM, false);
        break;
    }

    debug("Clean up.\n");

    munmap(g_shm, sizeof(dp_mnt_shm_t));
    return ret;
}

static void proc_exit_handler(int signal)
{
    int i, status, exit_status;
    pid_t pid;

    /* Wait for a child process to exit */
    while (1) {
        // waitpid() can be called in signal handler
        pid = waitpid(WAIT_ANY, &status, WNOHANG);
        if (pid <= 0) {
            return;
        }

        if (WIFEXITED(status)) {
            exit_status = WEXITSTATUS(status);
        } else {
            exit_status = -1;
        }

        for (i = 0; i < PROC_MAX; i ++) {
            if (pid != g_procs[i].pid) {
                continue;
            }

            g_procs[i].exit_status = exit_status;
            g_procs[i].exit_count ++;
            g_procs[i].running = false;
        }
    }
}

static void dp_stop_handler(int signal)
{
    g_procs[PROC_DP].active = false;
}

static void dp_start_handler(int signal)
{
    g_procs[PROC_DP].active = true;
}

static void check_heartbeat(void)
{
    int i;

    if (!g_procs[PROC_DP].active) {
        return;
    }

    for (i = 0; i < MAX_DP_THREADS; i ++) {
        if (!g_shm->dp_active[i]) {
            continue;
        }

        if (g_shm->dp_hb[i] != g_dp_last_hb[i]) {
           g_dp_last_hb[i] = g_shm->dp_hb[i];
           g_dp_miss_hb[i] = 0;
           continue;
        }

        g_dp_miss_hb[i] ++;
        // Suppress log for timer drifting. Only print when count is large than 1.
        if (g_dp_miss_hb[i] > 1) {
            debug("dp%d heartbeat miss count=%u hb=%u\n", i, g_dp_miss_hb[i], g_dp_last_hb[i]);
        }
        if (g_dp_miss_hb[i] > DP_MISS_HB_MAX) {
            debug("kill dp for heartbeat miss.\n");
            stop_proc(PROC_DP, SIGSEGV, false);

            g_dp_miss_hb[i] = 0;
        }
    }
}

static void help(const char *prog)
{
    printf("%s:\n", prog);
    printf("    h: help\n");
    printf("    c: start controller\n");
    printf("    d: start enforcer together with controller\n");
    printf("    r: start enforcer\n");
    printf("    s: start scanner\n");
}

int main (int argc, char **argv)
{
    int i, ret;
    struct timeval tmo;
    fd_set read_fds;

    int arg = 0;
    while (arg != -1) {
        arg = getopt(argc, argv, "hcdrs");

        switch (arg) {
        case -1:
            break;
        case 'c':
            g_mode = MODE_CTRL;
            break;
        case 'd':
            g_mode = MODE_CTRL_AGENT;
            break;
        case 'r':
            g_mode = MODE_AGENT;
            break;
        case 's':
            g_mode = MODE_SCANNER;
            break;
        case 'h':
        default:
            help(argv[0]);
            exit(0);
        }
    }

    signal(SIGTERM, exit_handler);
    signal(SIGBUS, exit_handler);
    signal(SIGINT, exit_handler);
    signal(SIGQUIT, exit_handler);
    signal(SIGCHLD, proc_exit_handler);
    signal(40, dp_stop_handler);
    signal(41, dp_start_handler);

    g_shm = create_shm(sizeof(dp_mnt_shm_t));
    if (g_shm == NULL) {
        debug("Unable to create shared memory. Exit!\n");
        return -1;
    }

    debug("%s starts, pid=%d\n", argv[0], getpid());

    for (i = 0; i < MAX_DP_THREADS; i ++) {
        g_dp_last_hb[i] = g_dp_miss_hb[i] = g_shm->dp_hb[i] = 0;
    }

    ret = 0;
    switch (g_mode) {
    case MODE_CTRL:
        g_procs[PROC_CTRL].active = true;
        // disable scanner in controller
        // g_procs[PROC_SCANNER].active = true;

        if (access(g_procs[PROC_CTRL].path, F_OK) == 0) {
            g_procs[PROC_CTRL_OPA].active = true;
        }
        break;
    case MODE_AGENT:
        ret = system(SCRIPT_SYSCTL);

        g_procs[PROC_DP].active = true;
        g_procs[PROC_AGENT].active = true;

        ret = WEXITSTATUS(system(SCRIPT_CONFIG));
        if (ret != RC_CONFIG_TC && ret != RC_CONFIG_OVS && ret != RC_CONFIG_NOTC) {
            debug("Initial configuration failed rc=%d. Exit!\n", ret);
            return ret;
        }
        g_pipe_driver = ret;
        break;
    case MODE_CTRL_AGENT:
        ret = system(SCRIPT_SYSCTL);

        g_procs[PROC_CTRL].active = true;
        // disable scanner in controller
        // g_procs[PROC_SCANNER].active = true;
        g_procs[PROC_DP].active = true;
        g_procs[PROC_AGENT].active = true;

        if (access(g_procs[PROC_CTRL].path, F_OK) == 0) {
            g_procs[PROC_CTRL_OPA].active = true;
        }

        ret = WEXITSTATUS(system(SCRIPT_CONFIG));
        if (ret != RC_CONFIG_TC && ret != RC_CONFIG_OVS && ret != RC_CONFIG_NOTC) {
            debug("Initial configuration failed rc=%d. Exit!\n", ret);
            return ret;
        }
        g_pipe_driver = ret;
        break;
    case MODE_SCANNER:
        g_procs[PROC_SCANNER_STANDALONE].active = true;
        break;
    }

    while (1) {
        if (g_exit_signal == 1) {
            ret = exit_monitor();
            debug("monitor exit[%d]", ret);
            sleep(3);       // wait for consul exit
            exit(0);
        }

        // stop/start process
        for (i = 0; i < PROC_MAX; i ++) {
            if (g_procs[i].active && !g_procs[i].running) {
                if (g_procs[i].pid > 0) {
                    // Previous process exited.
                    debug("Process %s exit status %d, pid=%d\n",
                          g_procs[i].name, g_procs[i].exit_status, g_procs[i].pid);

                    g_procs[i].pid = 0;

                    switch (i) {
                    case PROC_CTRL:
                    case PROC_AGENT:
                    case PROC_DP:
                        if (g_procs[i].exit_count > PROC_EXIT_LIMIT) {
                            exit_monitor();
                            exit(g_procs[i].exit_status & 0xff);
                        }
                        break;
                    }

                    if (g_exit_monitor_on_proc_exit == 1) {
                        debug("Process %s exit. Monitor Exit.\n",
                              g_procs[i].name);
                        exit_monitor();
                        exit(g_procs[i].exit_status & 0xff);
                    }

                    if (g_procs[i].exit_status == (-2 & 0xff)) {
                        debug("Process %s exit with non-recoverable return code. Monitor Exit!!\n",
                              g_procs[i].name);
                        exit_monitor();
                        exit(-2);
                    }

                    g_procs[i].exit_status = 0;

                    stop_related_proc(i);
                }

                start_proc(i);
            } else if (!g_procs[i].active && g_procs[i].pid > 0) {
                stop_proc(i, SIGTERM, true);
            }
        }

        tmo.tv_sec = 1;
        tmo.tv_usec = 0;

        FD_ZERO(&read_fds);
        ret = select(0, &read_fds, NULL, NULL, &tmo);

        if (ret == 0) {
            check_heartbeat();
        }
    }
    return 0;
}
