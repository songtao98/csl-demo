#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pidComm.h"
#include "sched_jit.h"
#include "runqslower.h"
#include "bpf/runqslower.skel.h"

unsigned int nr_cpus;
FILE *filep = NULL;
static volatile sig_atomic_t exiting = 0;
char log_dir[] = "/var/log/sysak/runqslow/";
char defaultfile[] = "/var/log/sysak/runqslow/runqslow.log";
char filename[256] = {0};

struct env {
	pid_t pid;
	pid_t tid;
	unsigned long span;
	__u64 threshold;
	bool previous;
	bool verbose;
	bool summary;
	struct sched_jit_summary *sump;
	char *shm_p;
} env = {
	.span = 0,
	.threshold = 50*1000*1000,
	.shm_p = NULL,
};

const char *argp_program_version = "runqslower 0.1";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [-h] [-s SPAN] [-t TID] [-S SUM] [-f LOG] [-P] [threshold]\n"
"\n"
"EXAMPLES:\n"
"    runqslower          # trace latency higher than 50ms (default)\n"
"    runqslower -f a.log # record result to a.log (default ~/sysak/runqslow/runqslow.log)\n"
"    runqslower 12       # trace latency higher than 12 ms\n"
"    runqslower -p 123   # trace pid 123\n"
"    runqslower -t 123   # trace tid 123 (use for threads only)\n"
"    schedmoni -s 10     # monitor for 10 seconds\n"
"    schedmoni -S shm_f  # log summary info to sharememory shm_f\n"
"    runqslower -P       # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "tid", 't', "TID", 0, "Thread TID to trace"},
	{ "span", 's', "SPAN", 0, "How long to run"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "summary", 'S', "SUM", 0, "Output the summary info" },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID" },
	{ "logfile", 'f', "LOGFILE", 0, "logfile for result"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int prepare_dictory(char *path)
{
	int ret;

	ret = mkdir(path, 0777);
	if (ret < 0 && errno != EEXIST)
		return errno;
	else
		return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *p;
	static int pos_args;
	int pid, shm_fd;
	long long threshold;
	unsigned long span;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'S':
		shm_fd = shm_open(arg, O_RDWR, 0666);
		if (shm_fd < 0) {
			/* we do not use summary, use detail instead. */
			fprintf(stdout, "shm_open %s: %s", arg, strerror(errno));
			break;
		}

		p  = mmap(NULL, sizeof(struct sched_jit_summary)+32,
			PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
		if (!p) {
			fprintf(stdout, "mmap %s: %s", arg, strerror(errno));
			break;
		}
		env.summary = true;
		env.sump = (struct sched_jit_summary *)p;
		break;
	case 'P':
		env.previous = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case 's':
		errno = 0;
		span = strtoul(arg, NULL, 10);
		if (errno || span <= 0) {
			fprintf(stderr, "Invalid SPAN: %s\n", arg);
			argp_usage(state);
		}
		env.span = span;
		break;
	case 'f':
		if (strlen(arg) < 2)
			strncpy(filename, defaultfile, sizeof(filename));
		else
			strncpy(filename, arg, sizeof(filename));
		filep = fopen(filename, "w+");
		if (!filep) {
			int ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), filename);
			return ret;
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		threshold = strtoll(arg, NULL, 10);
		if (errno || threshold <= 0) {
			fprintf(stderr, "Invalid delay (in ms): %s\n", arg);
			argp_usage(state);
		}
		env.threshold = threshold*1000*1000;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_alarm(int signo)
{
	exiting = 1;
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void fill_maxN(struct jit_maxN *maxN, const struct rqevent *e)
{
	maxN->delay = e->delay;
	maxN->cpu = e->cpuid;
	maxN->pid = e->pid;
	maxN->stamp = e->stamp;
	strncpy(maxN->comm, e->task, 16);
}

static void update_summary(struct sched_jit_summary* summary, const struct rqevent *e)
{
	int i, ridx;
	char buf[CONID_LEN] = {0};

	summary->num++;
	summary->total += e->delay;

	if (e->delay < 10) {
		summary->less10ms++;
	} else if (e->delay < 50) {
		summary->less50ms++;
	} else if (e->delay < 100) {
		summary->less100ms++;
	} else if (e->delay < 500) {
		summary->less500ms++;
	} else if (e->delay < 1000) {
		summary->less1s++;
	} else {
		summary->plus1s++;
	}

	ridx = summary->num % CPU_ARRY_LEN;
	summary->lastN_array[ridx].cpu = e->cpuid;
	summary->lastN_array[ridx].delay = e->delay;
	if (get_container(buf, e->pid))
		strncpy(summary->lastN_array[ridx].con, "000000000000", sizeof(summary->lastN_array[ridx].con));
	else
		strncpy(summary->lastN_array[ridx].con, buf, sizeof(summary->lastN_array[ridx].con));

	if (e->delay > summary->topNmin) {
		__u64 tmp;
		int idx;
		struct jit_maxN *maxi;

		idx = 0;
		tmp = summary->maxN_array[0].delay;
		/* sort: user insert sort */
		for (i = 1; i < CPU_ARRY_LEN; i++) {
			maxi = &summary->maxN_array[i];
			if (tmp > maxi->delay) {
				tmp = maxi->delay;
				idx = i;
			}
		}
		summary->topNmin = tmp;
		summary->min_idx = idx;
		fill_maxN(&summary->maxN_array[idx], e);
	} 
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct rqevent tmpe, *e;
	const struct rqevent *ep = data;
	struct tm *tm;
	char ts[64];
	time_t t;

	tmpe = *ep;
	e = &tmpe;
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%F %H:%M:%S", tm);
	e->delay = e->delay/(1000*1000);
	if (env.summary) {
		if (e->cpuid > nr_cpus - 1)
			return;
		update_summary(env.sump, e);
	} else {
		if (env.previous)
			fprintf(filep, "%-21s %-6d %-16s %-8d %-10llu %-16s %-6d\n",
				ts, e->cpuid, e->task, e->pid,
				e->delay, e->prev_task, e->prev_pid);
		else
			fprintf(filep, "%-21s %-6d %-16s %-8d %-10llu\n",
				ts, e->cpuid, e->task, e->pid, e->delay);
	}
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	int i, err, map_fd;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct runqslower_bpf *obj;
	struct perf_buffer_opts pb_opts = {};
	struct args args = {};

	err = prepare_dictory(log_dir);
	if (err)
		return err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (!filep) {
		filep = fopen(defaultfile, "w+");
		if (!filep) {
			err = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), defaultfile);
			return err;
		}
	}

	libbpf_set_print(libbpf_print_fn);

	bump_memlock_rlimit();

	obj = runqslower_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = runqslower_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	i = 0;
	map_fd = bpf_map__fd(obj->maps.argmap);
	args.targ_tgid = env.pid;
	args.targ_pid = env.tid;
	args.filter_pid = getpid();
	args.threshold = env.threshold;

	if (!env.summary) {
		if (env.previous)
			fprintf(filep, "%-21s %-6s %-16s %-8s %-10s %-16s %-6s\n",
				"TIME(runslw)", "CPU", "COMM", "TID", "LAT(ms)", "PREV COMM", "PREV TID");
		else
			fprintf(filep, "%-21s %-6s %-16s %-8s %-10s\n",
				"TIME(runslw)", "CPU", "COMM", "TID", "LAT(ms)");
	} else {
		memset(env.sump, 0, sizeof(struct sched_jit_summary));
	}

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64, &pb_opts);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR ||
		signal(SIGALRM, sig_alarm) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.span)
		alarm(env.span);

	bpf_map_update_elem(map_fd, &i, &args, 0);
	if (err) {
		fprintf(stderr, "Failed to update flag map\n");
		goto cleanup;
	}

	err = runqslower_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	runqslower_bpf__destroy(obj);
	if (env.sump) {
		munmap(env.sump, sizeof(struct sched_jit_summary)+32);
	}

	return err != 0;
}
