/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            2

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (512*2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  6000 //1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          16

/** @def APPL_MODE_PKT_BURST
 * @brief The application will handle pakcets in bursts
 */
#define APPL_MODE_PKT_BURST    0

/** @def APPL_MODE_PKT_QUEUE
 * @brief The application will handle packets in queues
 */
#define APPL_MODE_PKT_QUEUE    1

/** @def APPL_MODE_PKT_SCHED
 * @brief The application will handle packets with sheduler
 */
#define APPL_MODE_PKT_SCHED    2

/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define QUEUE_THRESHOLD  512	//10000 [VG]
#define DQCOUNT_INVALID -1
#define MAX_PROB 4294967295
#define PIE_SCALE 8


/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;		/**< Number of CPUs to use */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;


struct dev_if_
{
   odp_pktio_t pktio;
   odp_pktin_queue_t pktin;
   odp_pktout_queue_t pktout;
} dev1_if, dev2_if;


/**
 * Thread specific arguments
 */
typedef struct {
   struct dev_if_ *dev1;
   struct dev_if_ *dev2;
   int  route;
     
} thread_args_t;


/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/* parameters used */
struct pie_params {
	uint64_t target;	/* user specified target delay in odp time */
	uint32_t tupdate;		/* timer frequency (in jiffies) */
	uint32_t limit;		/* number of packets that can be enqueued */
	uint32_t alpha;		/* alpha and beta are between 0 and 32 */
	uint32_t beta;		/* and are used for shift relative to 1 */
	bool ecn;		/* true if ecn is enabled */
	bool bytemode;		/* to scale drop early prob based on pkt size */
}params;

/* variables used */
struct pie_vars {
	uint32_t prob;		/* probability but scaled by u32 limit. */
	int64_t burst_time;
	uint64_t qdelay;
	uint64_t qdelay_old;
	int dq_count;		/* measured in bytes */
	odp_time_t dq_tstamp;	/* drain rate */
	uint32_t avg_dq_rate;	/* bytes per pschedtime tick,scaled */
	uint32_t queue_len_old;		/* in bytes */
}vars;

/* statistics gathering */
struct pie_stats {
	uint32_t packets_in;		/* total number of packets enqueued */
	uint32_t dropped;		/* packets dropped due to pie_action */
	uint32_t overlimit;		/* dropped due to lack of space in queue */
	uint32_t maxq;			/* maximum queue size */
	uint32_t ecn_mark;		/* packets marked with ECN */
	uint32_t queue_len;		/* queue length */
}stats;



/* ODP parameters*/
odp_timer_pool_t tp;
odp_pool_t pool;
odp_pool_param_t pool_params;


/** Global pointer to args */
static args_t *args;

/* helper funcs */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
//static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
//static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/*Initialize PIE parameters*/
static void pie_params_init(odp_timer_pool_t *);
static void pie_vars_init();
static bool drop_early(odp_queue_t, uint32_t);
static void calculate_probability();
static void pie_process_dequeue(odp_packet_t [], int);


/* initialise PIE params */
static void pie_params_init(odp_timer_pool_t *tpool)
{	
	params.alpha = 2;
	params.beta = 20;
	params.tupdate = 30*1000000; /* 30 ms */         
	params.limit = 1000; 			 /* default of 1000 packets */
	params.target = odp_timer_ns_to_tick(*tpool, 1000000ULL * 20);  /* 20 ms */
	params.ecn = false;
	params.bytemode = false;
}

/* initialise PIE vars */
static void pie_vars_init()
{
	vars.dq_count = DQCOUNT_INVALID;
	vars.avg_dq_rate = 0;
	vars.burst_time = 100*1000;//100*1000000;   [VG]
}


/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 * @param mode Packet processing mode for this device (BURST or QUEUE)
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool, int mode)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);

	switch (mode) {
	case  APPL_MODE_PKT_BURST:
		pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
		break;
	case APPL_MODE_PKT_QUEUE:
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
		break;
	case APPL_MODE_PKT_SCHED:
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
		break;
	default:
		EXAMPLE_ABORT("invalid mode %d\n", mode);
	}

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", dev);

	odp_pktin_queue_param_init(&pktin_param);

	if (mode == APPL_MODE_PKT_SCHED)
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", dev);

	if (odp_pktout_queue_config(pktio, NULL))
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", dev);

	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	printf("  created pktio:%02" PRIu64
	       ", dev:%s, queue mode (ATOMIC queues)\n"
	       "  \tdefault pktio%02" PRIu64 "\n",
	       odp_pktio_to_u64(pktio), dev,
	       odp_pktio_to_u64(pktio));

	return pktio;
}


/**
 * Packet IO loopback worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_init_thread(char *dev, struct dev_if_ *dev_if)
{
	dev_if->pktio = odp_pktio_lookup(dev);
	if (dev_if->pktio == ODP_PKTIO_INVALID) {
		printf("  Error: lookup of pktio  failed\n");
		return NULL;
	}

	if (odp_pktin_queue(dev_if->pktio, &dev_if->pktin, 1) != 1) {
		printf("   Error: no pktin queue\n");
		//return NULL;
	}

	if (odp_pktout_queue(dev_if->pktio, &dev_if->pktout, 1) != 1) {
		printf(" Error: no pktout queue\n");
		return NULL;
	}
        return NULL;
}

static void *pktio_thread_connect(void *arg)
{
        int thr;
        thread_args_t *thr_args;
        struct dev_if_ *dev1,*dev2;
        int pkts, pkts_ok;
        odp_packet_t pkt_tbl[MAX_PKT_BURST];
        unsigned long pkt_cnt = 0;
        unsigned long err_cnt = 0;
        unsigned long tmp = 0;
	stats.queue_len = 0;
	bool enqueue = false;
	thr = odp_thread_id();	
	thr_args = arg;

        dev1 = thr_args->dev1;
        dev2 = thr_args->dev2;

        //printf("\n====> thread created [%02i]==> %d \n",thr,thr_args->route);
      
	/* Loop packets */
	for (;;) {
		pkts = odp_pktin_recv(dev1->pktin, pkt_tbl, MAX_PKT_BURST);
		if (pkts > 0) {
			/* Drop packets with errors */
			pkts_ok = drop_err_pkts(pkt_tbl, pkts);
			if (pkts_ok > 0) {
				int sent;

				sent = odp_pktout_send(dev2->pktout, pkt_tbl,
						       pkts_ok);
				if(sent>0 && thr_args->route == 10)
				{
					stats.queue_len+=odp_packet_seg_len(pkt_tbl[sent]);
					//printf("\nqueue length ---1 = %d, thread=%d\n", stats.queue_len, thr);
				}
                                if(thr_args->route == 10) 
				{
                                   //printf(" [%02i] packet dev1 --> dev2 \n",thr);  
                                } else 
				{
                                   //printf(" [%02i] --> packet dev2 --> dev1 \n",thr); 
                                }
				sent = sent > 0 ? sent : 0;
				/*
				if (odp_unlikely(sent < pkts_ok)) {
					err_cnt += pkts_ok - sent;
					do
					{	
						odp_packet_free(pkt_tbl[sent]);
						stats.queue_len-=odp_packet_seg_len(pkt_tbl[sent]);
					}
					while (++sent < pkts_ok);
				}*/

				if(thr_args->route == 10)
				{		
					if (!drop_early(pkt_tbl[sent], odp_packet_seg_len(pkt_tbl[sent]))) 
					{
						enqueue = true;
					}

					calculate_probability(); 

					/* If queue length is greater than queue limit, ignore packets. */
					if (stats.queue_len > SHM_PKT_POOL_BUF_SIZE )
					{
						//printf("\nqueue len ---2 = %d, thread = %d\n",stats.queue_len, thr);
						stats.overlimit++;
						pie_process_dequeue(pkt_tbl, sent);
						continue;
					}
					
				}
			}

			if (odp_unlikely(pkts_ok != pkts))
				EXAMPLE_ERR("Dropped frames:%u - err_cnt:%lu\n",
					    pkts-pkts_ok, ++err_cnt);

			/* Print packet counts every once in a while */
			tmp += pkts_ok;
			if (odp_unlikely((tmp >= 100000) || /* OR first print:*/
			    ((pkt_cnt == 0) && ((tmp-1) < MAX_PKT_BURST)))) {
				pkt_cnt += tmp;
				printf("   pkt_cnt:%lu\n", pkt_cnt);
				fflush(NULL);
				tmp = 0;
			}
		}
	}
	return NULL;
}


/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int num_workers;
	int i;
	int cpu;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
        odp_cpumask_t thd_mask[2];
	odp_timer_pool_param_t tparams;
        

	args = calloc(1, sizeof(args_t));
	if (args == NULL) {
		EXAMPLE_ERR("Error: args mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
#ifdef __SUDEEP__
	print_info(NO_PATH(argv[0]), &args->appl);
#endif
	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	//if (args->appl.cpu_count)
	//	num_workers = args->appl.cpu_count;

	/* Get default worker cpumask */
	//num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/*Initialize ODP timer pool parameters*/
	tparams.res_ns = 2 * ODP_TIME_MSEC_IN_NS;
	tparams.min_tmo = 0;
	tparams.max_tmo = 10000 * ODP_TIME_SEC_IN_NS;
	tparams.num_timers = num_workers; /* One timer per worker */
	tparams.priv = 0; /* Shared */
	tparams.clk_src = ODP_CLOCK_CPU;	

	/* Create timer pool */
	tp = odp_timer_pool_create("timer_pool", &tparams);
	if (tp == ODP_TIMER_POOL_INVALID) {
		EXAMPLE_ERR("Timer pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_timer_pool_start();
           
	pie_params_init(&tp);



	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	//odp_pool_print(pool);

	/* Create a pktio instance for each interface */
	for (i = 0; i < args->appl.if_count; ++i)
		create_pktio(args->appl.if_names[i], pool, args->appl.mode);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < 1 ; ++i) {
		void *(*thr_run_func) (void *);
		int if_idx;

		if_idx = i % args->appl.if_count;

                // init for dev1 to dev2
                if_idx = 0 % args->appl.if_count;
                pktio_init_thread(args->appl.if_names[if_idx],&dev1_if);
                if_idx = 1 % args->appl.if_count; 
                pktio_init_thread(args->appl.if_names[if_idx],&dev2_if); 

                // thread for dev1 to dev2
                args->thread[0].dev1 = &dev1_if;
                args->thread[0].dev2 = &dev2_if; 
                args->thread[0].route = 10;
                thr_run_func = pktio_thread_connect;

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_cpumask_zero(&thd_mask[0]);
		odp_cpumask_set(&thd_mask[0], cpu);
		odph_linux_pthread_create(&thread_tbl[0], &thd_mask[0],
					  thr_run_func,
					  &args->thread[0],
					  ODP_THREAD_WORKER);
		cpu = odp_cpumask_next(&cpumask, cpu);

                // thread for dev2 to dev1
                args->thread[1].dev1 = &dev2_if;
                args->thread[1].dev2 = &dev1_if;
                args->thread[1].route = 20;
                thr_run_func = pktio_thread_connect;
                //printf("=============xdzxfzxzxczc");
                odp_cpumask_zero(&thd_mask[1]);
                odp_cpumask_set(&thd_mask[1], cpu);
                odph_linux_pthread_create(&thread_tbl[1], &thd_mask[1],
                                          thr_run_func,
                                          &args->thread[1],
                                          ODP_THREAD_WORKER);
                //cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	free(args->appl.if_names);
	free(args->appl.if_str);
	free(args);
	printf("Exit\n\n");

	return 0;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return pkt_cnt;
}

/**
 * Swap eth src<->dst and IP src<->dst addresses
 *
 * @param pkt_tbl  Array of packets
 * @param len      Length of pkt_tbl[]
 */
#ifdef __SUDEEP__
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ethaddr_t tmp_addr;
	odph_ipv4hdr_t *ip;
	odp_u32be_t ip_tmp_addr; /* tmp ip addr */
	unsigned i;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		if (odp_packet_has_eth(pkt)) {
			eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

			tmp_addr = eth->dst;
			eth->dst = eth->src;
			eth->src = tmp_addr;

			if (odp_packet_has_ipv4(pkt)) {
				/* IPv4 */
				ip = (odph_ipv4hdr_t *)
					odp_packet_l3_ptr(pkt, NULL);

				ip_tmp_addr  = ip->src_addr;
				ip->src_addr = ip->dst_addr;
				ip->dst_addr = ip_tmp_addr;
			}
		}
	}
}
#endif

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_PKT_SCHED;

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:+m:t:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = malloc(len);
			if (appl_args->if_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;

		case 'm':
			i = atoi(optarg);
			switch (i) {
			case 0:
				appl_args->mode = APPL_MODE_PKT_BURST;
				break;
			case 1:
				appl_args->mode = APPL_MODE_PKT_QUEUE;
				break;
			case 2:
				appl_args->mode = APPL_MODE_PKT_SCHED;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
                        appl_args->mode = APPL_MODE_PKT_BURST;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
#ifdef __SUDEEP__
static void print_info(char *progname, appl_args_t *appl_args)
{

	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	switch (appl_args->mode) {
	case APPL_MODE_PKT_BURST:
		PRINT_APPL_MODE(APPL_MODE_PKT_BURST);
		break;
	case APPL_MODE_PKT_QUEUE:
		PRINT_APPL_MODE(APPL_MODE_PKT_QUEUE);
		break;
	case APPL_MODE_PKT_SCHED:
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED);
		break;
	}
	printf("\n\n");
	fflush(NULL);
}
#endif
/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2,eth3 -m 0\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -m, --mode      0: Receive and send directly (no queues)\n"
	       "                  1: Receive and send via queues.\n"
	       "                  2: Receive via scheduler, send via queues.\n"
	       "  -h, --help           Display help and exit.\n"
	       " environment variables: ODP_PKTIO_DISABLE_NETMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

/*
 * Drop the packet early if current delay exceeds
 */
static bool drop_early(odp_queue_t inq, uint32_t packet_size)
{
	//struct pie_sched_data *q = qdisc_priv(sch);
	//u32 rnd;
	uint32_t local_prob = vars.prob;
	//uint32_t mtu = psched_mtu(qdisc_dev(sch));                                    //odp_pktio_mtu()

	/* If there is still burst allowance left skip random early drop */
	if (vars.burst_time > 0)
		return false;

	/* If current delay is less than half of target, and
	 * if drop prob is low already, disable early_drop
	 */
	if ((vars.qdelay < params.target/ 2)
	    && (vars.prob < MAX_PROB / 5))
		return false;

	/* If we have fewer than 2 mtu-sized packets, disable drop_early,
	 * similar to min_th in RED
	 */
	if (stats.queue_len < 2 * SHM_PKT_POOL_BUF_SIZE )				//to be updated
		return false;

	/* If bytemode is turned on, use packet size to compute new
	 * probablity. Smaller packets will have lower drop prob in this case
	 */
//	if (q->params.bytemode && packet_size <= mtu)
//		local_prob = (local_prob / mtu) * packet_size;
//	else
//		local_prob = q->vars.prob;

//	rnd = random32();
//	if (rnd < local_prob)
//		return true;

	return false;
}

/* Calculate packet drop probability */
static void calculate_probability()
{
	uint64_t qdelay = 0;	/* in pschedtime */
	uint64_t qdelay_old = vars.qdelay;	/* in pschedtime */
	int32_t delta = 0;		/* determines the change in probability */
	uint32_t oldprob;
	uint32_t alpha, beta;
	bool update_prob = true;
	uint64_t err;
	vars.qdelay_old = vars.qdelay;


	
	if (vars.avg_dq_rate > 0)
		qdelay = (stats.queue_len << PIE_SCALE) / vars.avg_dq_rate; 
	else
		qdelay = 0;

	/* If qdelay is zero and pool-len is not, it means pool-len is very small, less
	 * than dequeue_rate, so we do not update probabilty in this round
	 */
	if (qdelay == 0 && stats.queue_len != 0)
		update_prob = false;

	/* In the algorithm, alpha and beta are between 0 and 2 with typical
	 * value for alpha as 0.125. In this implementation, we use values 0-32
	 * passed from user space to represent this. Also, alpha and beta have
	 * unit of HZ and need to be scaled before they can used to update
	 * probability. alpha/beta are updated locally below by 1) scaling them
	 * appropriately 2) scaling down by 16 to come to 0-2 range.
	 * Please see paper for details.
	 *
	 * We scale alpha and beta differently depending on whether we are in
	 * light, medium or high dropping mode.
	 */

	//err=odp_timer_ns_to_tick(tp, 1000000ULL * 10);
	//printf("\nerr = %d\n", err);	
	if (vars.prob < MAX_PROB / 100) {
		alpha =
		    (params.alpha * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 7;
		beta =
		    (params.beta * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 7;
	} else if (vars.prob < MAX_PROB / 10) {
		alpha =
		    (params.alpha * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 5;
		beta =
		    (params.beta * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 5;
	} else {
		alpha =
		    (params.alpha * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 4;
		beta =
		    (params.beta * (MAX_PROB / odp_timer_ns_to_tick(tp, 1000000ULL * 1000))) >> 4;
	}

	
	
	/* alpha and beta should be between 0 and 32, in multiples of 1/16 */
	delta += alpha * ((qdelay - params.target));
	delta += beta * ((qdelay - qdelay_old));

	oldprob = vars.prob;

	/* to ensure we increase probability in steps of no more than 2% */
	if (delta > (int) (MAX_PROB / (100 / 2)) &&
	    vars.prob >= MAX_PROB / 10)
		delta = (MAX_PROB / 100) * 2;

	/* Non-linear drop:
	 * Tune drop probability to increase quickly for high delays(>= 250ms)
	 * 250ms is derived through experiments and provides error protection
	 */

	if (qdelay > odp_timer_ns_to_tick(tp, 1000000ULL * 250))
		delta += MAX_PROB / (100 / 2);

	vars.prob += delta;

	if (delta > 0) {
		/* prevent overflow */
		if (vars.prob < oldprob) {
			vars.prob = MAX_PROB;
			/* Prevent normalization error. If probability is at
			 * maximum value already, we normalize it here, and
			 * skip the check to do a non-linear drop in the next
			 * section.
			 */
			update_prob = false;
		}
	} else {
		/* prevent underflow */
		if (vars.prob > oldprob)
			vars.prob = 0;
	}

	/* Non-linear drop in probability: Reduce drop probability quickly if
	 * delay is 0 for 2 consecutive Tupdate periods.
	 */

	if ((qdelay == 0) && (qdelay_old == 0) && update_prob)
		vars.prob = (vars.prob * 98) / 100;

	vars.qdelay = qdelay;
	vars.queue_len_old = stats.queue_len;

	/* We restart the measurement cycle if the following conditions are met
	 * 1. If the delay has been low for 2 consecutive Tupdate periods
	 * 2. Calculated drop probability is zero
	 * 3. We have atleast one estimate for the avg_dq_rate ie.,
	 *    is a non-zero value
	 */
	if ((vars.qdelay < params.target / 2) &&
	    (vars.qdelay_old < params.target / 2) &&
	    (vars.prob == 0) &&
	    (vars.avg_dq_rate > 0))
		pie_vars_init(&vars);
}


static void pie_process_dequeue(odp_packet_t odp_pkt_tbl[], int idx)
{
	int thr;

	thr = odp_thread_id();	
	/* If current queue is about 10 packets or more and dq_count is unset
	 * we have enough packets to calculate the drain rate. Save
	 * current time as dq_tstamp and start measurement cycle.
	 */

	if (stats.queue_len >= QUEUE_THRESHOLD && vars.dq_count == DQCOUNT_INVALID)
	{
		//printf("\nqueue length is greater than threshold\n");
		vars.dq_tstamp = odp_time_global();
		vars.dq_count = 0;
	}

	/* Calculate the average drain rate from this value.  If queue length
	 * has receded to a small value viz., <= QUEUE_THRESHOLD bytes,reset
	 * the dq_count to -1 as we don't have enough packets to calculate the
	 * drain rate anymore The following if block is entered only when we
	 * have a substantial queue built up (QUEUE_THRESHOLD bytes or more)
	 * and we calculate the drain rate for the threshold here.  dq_count is
	 * in bytes, time difference in psched_time, hence rate is in
	 * bytes/psched_time.
	 */

	if(stats.queue_len>0)
	{
		stats.queue_len-=odp_packet_seg_len(odp_pkt_tbl[idx]);
		//printf("\nqueue length ---3 = %d, thread = %d\n", stats.queue_len,thr);
		
		
			
			if (vars.dq_count != DQCOUNT_INVALID) 
			{	
					
				vars.dq_count += odp_packet_seg_len(odp_pkt_tbl[idx]) ;
				
				if (vars.dq_count >= QUEUE_THRESHOLD) 
				{
					
					odp_time_t now = odp_time_global();
					odp_time_t dtime = odp_time_diff(now,vars.dq_tstamp);
					uint32_t count = vars.dq_count<<PIE_SCALE;
					
					if (odp_time_to_ns(dtime) == 0)
						return;

					count = count/odp_time_to_ns(dtime);

					if (vars.avg_dq_rate == 0)
						vars.avg_dq_rate = count;
					else
						vars.avg_dq_rate =
						    (vars.avg_dq_rate-(vars.avg_dq_rate >> 3)) + (count >> 3);
					
					/* If the queue has receded below the threshold, we hold
					 * on to the last drain rate calculated, else we reset
					 * dq_count to 0 to re-enter the if block when the next
					 * packet is dequeued
					 */
					if (stats.queue_len < QUEUE_THRESHOLD)
						vars.dq_count = DQCOUNT_INVALID;
					else 
					{
						vars.dq_count = 0;
						vars.dq_tstamp = odp_time_global();
					}
					
					if (vars.burst_time > 0) 
					{
						if (vars.burst_time > odp_time_to_ns(dtime))

							vars.burst_time -= odp_time_to_ns(dtime);
						else
							vars.burst_time = 0;
					}
					
				}
			}
		
		
		
	}
	else
		printf("\nError in dequeue\n");	
}



