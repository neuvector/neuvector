#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "debug.h"
#include "apis.h"
#include "utils/helper.h"
#include "utils/rcu_map.h"

extern void *dp_timer_thr(void *args);
extern void *dp_bld_dlp_thr(void *args);
extern void *dp_data_thr(void *args);
extern void dp_ctrl_loop(void);
extern int dp_ctrl_send_json(json_t *root);
extern int dp_ctrl_send_binary(void *data, int len);
extern int dp_ctrl_threat_log(DPMsgThreatLog *log);
extern int dp_ctrl_traffic_log(DPMsgSession *log);
extern int dp_ctrl_connect_report(DPMsgSession *log, DPMonitorMetric *metric, int count_session, int count_violate);
extern void dp_ctrl_init_thread_data(void);

extern int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);

extern int dp_send_packet(io_ctx_t *context, uint8_t *pkt, int len);

__thread int THREAD_ID;
__thread char THREAD_NAME[32];

#define DEBUG_FILE "/var/log/agent/dp.log"

int g_running;
dp_mnt_shm_t *g_shm;
rcu_map_t g_ep_map;
struct cds_list_head g_subnet4_list; 
struct cds_list_head g_subnet6_list; 
struct timeval g_now;
int g_dp_threads = 0;
int g_stats_slot = 0;
char *g_in_iface;
pthread_mutex_t g_debug_lock;

io_callback_t g_callback;
io_config_t g_config;

static void dp_signal_dump_policy(int num)
{
    int thr_id;
    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_data_wait_ctrl_req_thr(CTRL_REQ_DUMP_POLICY, thr_id);
    }
}

static void dp_signal_exit(int num)
{
    g_running = false;
}

static inline int debug_ts(FILE *logfp)
{
    struct timeval now;
    struct tm *tm;

    if (g_now.tv_sec == 0) {
        //gettimeofday(&now, NULL);
        time_t t = get_current_time();
        tm = localtime((const time_t *)&t);
    } else {
        now = g_now;
        tm = localtime(&now.tv_sec);
    }

    return fprintf(logfp, "%04d-%02d-%02dT%02d:%02d:%02d|DEBU|%s|",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec, THREAD_NAME);
}

static int debug_stdout(bool print_ts, const char *fmt, va_list args)
{
    int len = 0;

    pthread_mutex_lock(&g_debug_lock);
    if (print_ts) {
        len = debug_ts(stdout);
    }
    len += vprintf(fmt, args);
    pthread_mutex_unlock(&g_debug_lock);

    return len;
}

int debug_file(bool print_ts, const char *fmt, va_list args)
{
    static FILE *logfp = NULL;

    if (logfp == NULL) {
        logfp = fopen(DEBUG_FILE, "a");

        if (logfp != NULL) {
            int flags;

            if ((flags = fcntl(fileno(logfp), F_GETFL, 0)) == -1) {
                flags = 0;
            }
            fcntl(fileno(logfp), F_SETFL, flags | O_NONBLOCK);
        } else {
            return debug_stdout(print_ts, fmt, args);
        }
    }

    int len = 0;

    pthread_mutex_lock(&g_debug_lock);
    if (print_ts) {
        len = debug_ts(logfp);
    }
    len += vfprintf(logfp, fmt, args);
    fflush(logfp);
    pthread_mutex_unlock(&g_debug_lock);

    return len;
}

static void *get_shm(size_t size)
{
    int fd;
    void *ptr;

    fd = shm_open(DP_MNT_SHM_NAME, O_RDWR, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return NULL;
    }

    ptr = mmap(NULL, sizeof(dp_mnt_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == NULL) {
        close(fd);
        return NULL;
    }

    close(fd);

    return ptr;
}

static int net_run(const char *in_iface)
{
    pthread_t timer_thr;
    pthread_t bld_dlp_thr;
    pthread_t dp_thr[MAX_DP_THREADS];
    int i, j, timer_thr_id, bld_dlp_thr_id, thr_id[MAX_DP_THREADS];
    bool thr_create[MAX_DP_THREADS];
    DEBUG_FUNC_ENTRY(DBG_INIT);

    g_running = true;

    signal(SIGTERM, dp_signal_exit);
    signal(SIGINT, dp_signal_exit);
    signal(SIGQUIT, dp_signal_exit);
    signal(SIGUSR1, dp_signal_dump_policy);

    for (j = 0; j < MAX_DP_THREADS; j++) {
        thr_create[j] = false;
    }
    // Calculate number of dp threads
    if (g_dp_threads == 0) {
        g_dp_threads = count_cpu();
    }
    if (g_dp_threads > MAX_DP_THREADS) {
        g_dp_threads = MAX_DP_THREADS;
    }

    dp_ctrl_init_thread_data();

    pthread_create(&timer_thr, NULL, dp_timer_thr, &timer_thr_id);

    pthread_create(&bld_dlp_thr, NULL, dp_bld_dlp_thr, &bld_dlp_thr_id);

    for (i = 0; i < g_dp_threads; i ++) {
        thr_id[i] = i;
        thr_create[i] = true;
        pthread_create(&dp_thr[i], NULL, dp_data_thr, &thr_id[i]);
    }

    if (in_iface != NULL) {
        sleep(2);
        dp_data_add_tap("/proc/1/ns/net", in_iface, "11:22:33:44:55:66", 0);
    }

    dp_ctrl_loop();

    pthread_join(timer_thr, NULL);
    pthread_join(bld_dlp_thr, NULL);
    for (i = 0; i < g_dp_threads; i ++) {
        if (thr_create[i]) {
            pthread_join(dp_thr[i], NULL);
        }
    }

    return 0;
}

static void help(const char *prog)
{
    printf("%s:\n", prog);
    printf("  h: help\n");
    printf("  d: debug flags\n");
    printf("     (none, all, int, error, ctrl, packet, session, timer, tcp, parser, log, ddos, policy, dlp)\n");
    printf("  p: pcap file or directory\n");
    printf("  s: standalone mode (listen to the control channel)\n");
}

// -- pcap

void init_dummy_ep(io_ep_t *ep);

static struct timeval tv_diff(struct timeval s, struct timeval e)
{
    struct timeval d;
    if (e.tv_usec < s.tv_usec) {
        d.tv_sec = e.tv_sec - s.tv_sec - 1;
        d.tv_usec = 1000000 + e.tv_usec - s.tv_usec;
    } else {
        d.tv_sec = e.tv_sec - s.tv_sec;
        d.tv_usec = e.tv_usec - s.tv_usec;
    }
    return d;
}

#include <pcap/pcap.h>
static int pcap_send_packet(io_ctx_t *context, uint8_t *pkt, int len)
{
    DEBUG_PACKET("Send %u\n", len);

    return len;
}

static void pcap_packet(char *user, struct pcap_pkthdr *hdr, uint8_t *pkt)
{
    io_ctx_t context;
    struct timeval last_now = g_now;

    context.dp_ctx = NULL;
    g_now = hdr->ts;
    context.tick = g_now.tv_sec;
    context.tap = true;
    context.quar = false;
    dpi_recv_packet(&context, pkt, hdr->caplen);

    struct timeval td = tv_diff(last_now, g_now);
    if (td.tv_sec > 0) {
        dpi_timeout(g_now.tv_sec);
    }
}


static int pcap_run(const char *path)
{
    struct stat st;

    memset(&st, 0, sizeof(st));
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            DIR *dir = opendir(path);
            struct dirent *file;

            if (dir == NULL) {
                return -1;
            }

            while ((file = readdir(dir)) != NULL) {
                if (file->d_name[0] == '.') {
                    continue;
                }

                char dir_path[1024];
                snprintf(dir_path, sizeof(dir_path), "%s/%s", path, file->d_name);
                printf("Enter: %s\n", dir_path);
                pcap_run(dir_path);
            }
        } else {
            pcap_t *pcap;
            char err[PCAP_ERRBUF_SIZE];

            pcap = pcap_open_offline(path, err);
            if (pcap == NULL) {
                printf("Cannot open pcap file: %s\n", path);
                return -1;
            }

            pcap_loop(pcap, -1, (pcap_handler)pcap_packet, NULL);

            pcap_close(pcap);

            return 0;
        }
    }

    return -1;
}

int pcap_send_json(json_t *root)
{
    return 0;
}

int pcap_threat_log(DPMsgThreatLog *log)
{
    return printf("Threat: id=%u action=%s\n",
                  ntohl(log->ThreatID), debug_action_name(log->Action));
}

int pcap_traffic_log(DPMsgSession *log)
{
    return sizeof(*log);
}

int pcap_connect_report(DPMsgSession *log, DPMonitorMetric *metric, int count_session, int count_violate)
{
    return sizeof(*log);
}

// ---

static int dp_ep_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_mac_t *ht_mac = STRUCT_OF(ht_node, io_mac_t, node);
    const uint8_t *mac = key;

    return memcmp(mac, &ht_mac->mac, sizeof(ht_mac->mac)) == 0 ? 1 : 0;
}

static uint32_t dp_ep_hash(const void *key)
{
    return sdbm_hash(key, ETH_ALEN);
}


int main(int argc, char *argv[])
{
    char *pcap = NULL;
    bool standalone = false;
    int arg = 0;
    struct rlimit core_limits;

    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);

    memset(&g_config, 0, sizeof(g_config));
    while (arg != -1) {
        arg = getopt(argc, argv, "hcd:i:j:n:p:s:v:");

        switch (arg) {
        case -1:
            break;
        case 'c':
            g_config.enable_cksum = true;
            break;
        case 'd':
            if (strcasecmp(optarg, "none") == 0) {
                g_debug_levels = 0;
            } else if (optarg[0] == '-') {
                g_debug_levels &= ~debug_name2level(optarg + 1);
            } else {
                g_debug_levels |= debug_name2level(optarg);
            }
            break;
        case 'i':
            g_in_iface = strdup(optarg);
            g_config.promisc = true;
            break;
        case 'n':
            g_dp_threads = atoi(optarg);
            break;
        case 'p':
            pcap = optarg;
            g_config.promisc = true;
            break;
        case 's':
            standalone = true;
            break;
        case 'v':
            if (strcasecmp(optarg, "thrt_tls_1dot0") == 0) {
                g_config.thrt_ssl_tls_1dot0 = true;
            }
            else if (strcasecmp(optarg, "thrt_tls_1dot1") == 0) {
                g_config.thrt_ssl_tls_1dot1 = true;
            }
            break;
        case 'h':
        default:
            help(argv[0]);
            exit(-2);
        }
    }

    setlinebuf(stdout);

    pthread_mutex_init(&g_debug_lock, NULL);
    rcu_map_init(&g_ep_map, 1, offsetof(io_mac_t, node), dp_ep_match, dp_ep_hash);
    CDS_INIT_LIST_HEAD(&g_subnet4_list);
    CDS_INIT_LIST_HEAD(&g_subnet6_list);

    init_dummy_ep(&g_config.dummy_ep);
    g_config.dummy_mac.ep = &g_config.dummy_ep;

    if (pcap != NULL) {
        g_callback.debug = debug_stdout;
        g_callback.send_packet = pcap_send_packet;
        g_callback.send_ctrl_json = dp_ctrl_send_json;
        g_callback.send_ctrl_binary = dp_ctrl_send_binary;
        g_callback.threat_log = pcap_threat_log;
        g_callback.traffic_log = pcap_traffic_log;
        g_callback.connect_report = pcap_connect_report;
        dpi_setup(&g_callback, &g_config);
        dpi_init(DPI_INIT);
        return pcap_run(pcap);
    } else if (standalone) {
        g_callback.debug = debug_stdout;
        g_callback.send_packet = dp_send_packet;
        g_callback.send_ctrl_json = dp_ctrl_send_json;
        g_callback.send_ctrl_binary = dp_ctrl_send_binary;
        g_callback.threat_log = dp_ctrl_threat_log;
        g_callback.traffic_log = dp_ctrl_traffic_log;
        g_callback.connect_report = dp_ctrl_connect_report;
        dpi_setup(&g_callback, &g_config);

        g_shm = calloc(1, sizeof(dp_mnt_shm_t));
        if (g_shm == NULL) {
            DEBUG_INIT("Unable to allocate shared memory.\n");
            return -1;
        }

        int ret = net_run(g_in_iface);

        free(g_shm);

        return ret;
    } else {
        g_callback.debug = debug_stdout;
        g_callback.send_packet = dp_send_packet;
        g_callback.send_ctrl_json = dp_ctrl_send_json;
        g_callback.send_ctrl_binary = dp_ctrl_send_binary;
        g_callback.threat_log = dp_ctrl_threat_log;
        g_callback.traffic_log = dp_ctrl_traffic_log;
        g_callback.connect_report = dp_ctrl_connect_report;
        dpi_setup(&g_callback, &g_config);

        g_shm = get_shm(sizeof(dp_mnt_shm_t));
        if (g_shm == NULL) {
            DEBUG_INIT("Unable to get shared memory.\n");
            return -1;
        }

        // Start
        int ret = net_run(g_in_iface);

        munmap(g_shm, sizeof(dp_mnt_shm_t));

        return ret;
    }

    return 0;
}
