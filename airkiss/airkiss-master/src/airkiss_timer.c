#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include "pthread.h"
#include <sys/socket.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h> 



#include "airkiss.h"

#define RX_80211_PKT_SIZE   (1500)
#define RX_BUF_SIZE         (3000)

#define debug_print(fmt, arg...) \
do { \
	printf(fmt, ##arg);\
} while (0)

typedef struct _RX_PKT {
    unsigned int  length;
    unsigned char  data[RX_80211_PKT_SIZE];
} RX_PKT;


airkiss_context_t akcontext;
uint8_t cur_channel = 1;
airkiss_config_t config;
airkiss_result_t ak_result;

int ch_lst[13] = {1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12};
static int ch_index = 0;	



#define CMDLEN		256
static char cmd[CMDLEN];

int get_ap_linked = 0;


void do_system(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	va_end(ap);
	
	sprintf(cmd, "%s", cmd);
	system(cmd);

	return;
}

#define WEBCHAT_PORT 10000

int notify_webchat(unsigned char random)
{
    int i;
    int fd;
    int enabled = 1;
    int err;
    struct sockaddr_in addr;
    unsigned int usecs = 1000*50;
	socklen_t len;
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("192.168.0.255");;
    addr.sin_port = htons(WEBCHAT_PORT);
    
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        debug_print("get socket err:%d\n", errno);
        return -1;
    } 
    
    err = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&enabled, sizeof(enabled));
	if (err == -1) {
        close(fd);
        return -1;
    }
	
	err = getsockopt(fd, SOL_SOCKET, SO_BROADCAST, (void *)&enabled, &len);
	if (err < 0 ) {
		close(fd);
		return -1;
	}
	
	debug_print("getsockopt :SO_BROADCAST %d\n", enabled);
    
    debug_print("Sending random to broadcast..\n");
	
    for ( i = 0; i < 50; i++) {

repeat_send:
        err = sendto(fd, (unsigned char *)&random, 1, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr));
		if (err < 0) {
			debug_print("\n notify_webchat err:%d errno :%d %s\n", err, errno, strerror(errno));
			if (EINTR == errno) {
				usleep(usecs);
				goto repeat_send;
			}
		}
		
        usleep(usecs);
    }

    close(fd);
	
    return 0;
}


inline int set_channel(int ch_index)
{
	struct timeval cur;
	
    char cmd[128] = "\0";

	#if 0
	{
		int sock;
		struct iwreq wrq;

		memset(&wrq, 0, sizeof(struct iwreq));
		strncpy(wrq.ifr_name, "ra0", IFNAMSIZ);

		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
		if (sock > 0) {
			
			ioctl(sock, SIOCGIWPRIV, (void *)&wrq);
			ioctl(sock, SIOCIWFIRSTPRIV + 0x02, (void *)&wrq);
			
			close(sock);
		}
		
	}
	#endif
	//gettimeofday(&cur, NULL);
	//debug_print("change channel:%02d usec:%llu ch_index :%d\n", ch_lst[ch_index], (long long)((long long)cur.tv_usec + (long long)(cur.tv_sec)*1000*1000)/100000, ch_index);

	
    sprintf(cmd, "iwpriv ra0 set Channel=%d", ch_lst[ch_index]);
	system(cmd);    
    

    return 0;
}

static void time_callback(void)
{	
    char cmd[128];	
    
    if (++ch_index >= 13)
        ch_index = 0;

    set_channel(ch_index);
}

static void miscellaneous_mode_enable(void)
{
    printf("start monitor mode\n");
    system("iwpriv ra0 airkiss start");
    system("iwpriv ra0 set MonitorMode=2");
	system("ifconfig mon0 up");

	return;
}

static void miscellaneous_mode_disable(void)
{
    system("iwpriv ra0 set MonitorMode=0");
	system("iwpriv ra0 airkiss stop");
	system("ifconfig mon0 down");

	debug_print("airkiss process stop");

	return;
}


static void exit_airkiss(int sig)
{
	miscellaneous_mode_disable();
	
    exit(1);
}

static void udhcpc_notify(int sig)
{
	debug_print("sig :%d\n", sig);
	get_ap_linked = 1;
}

static void signal_handle(void)
{
    signal(SIGPIPE, &exit_airkiss);//pipe broken
    signal(SIGINT,  &exit_airkiss);//ctrl+c
    signal(SIGTERM, &exit_airkiss);//kill
    signal(SIGSEGV, &exit_airkiss);//segmentfault
    signal(SIGBUS,  &exit_airkiss);//bus error/**/
    signal(SIGUSR1, &udhcpc_notify);
}

static void hexdump(unsigned char *buf, int length)
{
	int i;
	
	printf("recv data: %d\n", length);
	for (i = 0; i < length; i++) {
		if ( i != 0 && ((i % 16) == 0)) {
			printf("\n");
		}
		printf("%02x ", buf[i]);
	}
	
	printf("\n end\n");
}

int ap_get_encrytpye(char *air_ssid, int air_channel, char *AutoMode, char *EncType)
{
	FILE *pp;
	char cmd[256], *ptr, wif[5];
	char channel[4], ssid[186], bssid[20], security[23];
	char signal[9], mode[7], ext_ch[7], net_type[3];
	int i, space_start;

	int j=0;	
	int ret = 0;

	strcpy(wif, "ra0");
	do_system("iwpriv %s set SiteSurvey=1", wif);
	
	sleep(5); // for get the SCAN result. (2G + 5G may enough for 5 seconds)
	
	sprintf(cmd, "iwpriv %s get_site_survey", wif);
	if ( !(pp = popen(cmd, "r")) ) {
		debug_print("execute get_site_survey fail!");
		return -1;
	}

	memset(cmd, 0, sizeof(cmd));
	fgets(cmd, sizeof(cmd), pp);	//前两行非数据
	fgets(cmd, sizeof(cmd), pp);
	
	while (fgets(cmd, sizeof(cmd), pp)) {
		if (strlen(cmd) < 4)
			break;
		
		ptr = cmd;
		sscanf(ptr, "%s ", channel);
		
		ptr += 37;
		sscanf(ptr, "%s %s %s %s %s %s", bssid, security, signal, mode, ext_ch, net_type);
		
		ptr = cmd+4;
		
		i = 0;
		while (i < 33) {
			if ((ptr[i] == ' ') && (i == 0 || ptr[i-1] != ' '))
				space_start = i;
			i++;
		}
		
		ptr[space_start] = '\0';
		strcpy(bssid, cmd+4);

		if ( !strcmp(bssid, air_ssid) && (atoi(channel) == air_channel) ) {
			debug_print("-----%s %s %s %s %s %s-----\n", bssid, security, signal, mode, ext_ch, net_type);
			
			if( (strstr(security, "none")) || (strstr(security, "NONE")) || (strstr(security, "OPEN")) ) {
				
				//strcpy(ap_Enc,"none");
				strcpy(AutoMode, "OPEN");
				strcpy(EncType, "NONE");
			} else if ((strstr(security,"WEP"))) {
			
				//strcpy(ap_Enc,"wep");
				strcpy(AutoMode, "SHARED");
				strcpy(EncType, "WEP");
				
				//nvram_bufset(RT2860_NVRAM,"ApCliDefaultKeyID","1");
				//nvram_bufset(RT2860_NVRAM,"ApCliKey1Type","1");
				
			} else if ((strstr(security,"WPA2"))) {
				
				if ((strstr(security,"TKIP"))) {
					
					//strcpy(ap_Enc,"wpa2_tkip");
					strcpy(AutoMode, "WPA2PSK");
					strcpy(EncType, "TKIP");
				} else {
				
					//strcpy(ap_Enc,"wpa2_aes");
					strcpy(AutoMode, "WPA2PSK");
					strcpy(EncType, "AES");
				}
			
			} else if ((strstr(security,"WPA"))) {
			
				if ((strstr(security,"TKIP"))) {
					
					//strcpy(ap_Enc,"wpa_tkip");
					strcpy(AutoMode, "WPAPSK");
					strcpy(EncType, "TKIP");
				} else {
				
					//strcpy(ap_Enc,"wpa_aes");
					strcpy(AutoMode, "WPAPSK");
					strcpy(EncType, "AES");
				}
			} else{
				//strcpy(ap_Enc,"wpa_aes");
				strcpy(AutoMode, "WPA2PSK");
				strcpy(EncType, "AES");
			}
		
			return 0;
		}

	}
	
	pclose(pp);


	return -1;
}

int apcli_enable(char *ssid, char *pwd, char *AutoMode, char *EncType, char *Chan)
{
	char cmd[256];
	
	do_system("iwpriv apcli0 set ApCliEnable=0");
	do_system("ifconfig apcli0 0.0.0.0");
	
	do_system("iwpriv apcli0 set ApCliSsid=%s", ssid);
	do_system("iwpriv apcli0 set ApCliWPAPSK=%s", pwd);
	do_system("iwpriv apcli0 set ApCliEncrypType=%s", EncType);
	do_system("iwpriv apcli0 set ApCliAuthMode=%s", AutoMode);

	if (0 == access("/var/run/udhcpc.pid", R_OK) ) {
		do_system("kill -9 `cat /var/run/udhcpc.pid`");
		do_system("rm -f /var/run/udhcpc.pid");
	} else if (0 == access("/var/run/udhcp", R_OK) ) {
		do_system("kill -9 `cat /var/run/udhcp`");
	}
	
	do_system("iwpriv apcli0 set ApCliEnable=1");
	
	sleep(1);
	
	do_system("udhcpc -i apcli0 -s /sbin/udhcpc.sh -p /var/run/udhcp");

	return 0;
}


int config_wifi(char *ssid, char *pwd, int channel)
{
	int i;
	int nvram_id;
	char AutoMode[20], EncType[20], Chan[20];
	
#define SCAN_COUNT 3

	for (i = 0; i < SCAN_COUNT; i++) {
		if (0 == ap_get_encrytpye(ssid, channel, AutoMode, EncType) ) {
			break;
		}
	}
	
	//默认扫描3次
	if (SCAN_COUNT == i) {
		debug_print("ssid %s scan fail.\n", ssid);
		return -1;
	}

	nvram_id = getNvramIndex("2860");
	if (nvram_id == -1) {
		return -1;
	}

	debug_print("AutoMode:%s EncType:%s\n", AutoMode, EncType);
	
	nvram_init(nvram_id);

	sprintf(Chan, "%d", channel);
	
	nvram_bufset(nvram_id, "AutoChannelSelect", "0");
	nvram_bufset(nvram_id, "Channel", Chan);
	
	//nvram_bufset(nvram_id, "ApCliBssid", ssid);
	
	nvram_bufset(nvram_id, "ApCliAuthMode", AutoMode);
	nvram_bufset(nvram_id, "ApCliEncrypType", EncType);

	
	nvram_bufset(nvram_id, "ApCliDefaultKeyID", "1");
	nvram_bufset(nvram_id, "ApCliKey1Type", "1");
	
	#if 1
	nvram_bufset(nvram_id, "ApCliKey2Type", "1");
	nvram_bufset(nvram_id, "ApCliKey3Type", "1");
	nvram_bufset(nvram_id, "ApCliKey4Type", "1");
	nvram_bufset(nvram_id, "ApCliKey1Str", "1");
	nvram_bufset(nvram_id, "ApCliKey2Str", "1");
	nvram_bufset(nvram_id, "ApCliKey3Str", "1");
	nvram_bufset(nvram_id, "ApCliKey4Str", "1");	
	#endif	
		
	nvram_bufset(nvram_id, "ApCliSsid", ssid);
	nvram_bufset(nvram_id, "ApCliWPAPSK", pwd);
	nvram_bufset(nvram_id, "ApCliEnable", "1");
		
	nvram_commit(nvram_id);
	
	nvram_close(nvram_id);

	apcli_enable(ssid, pwd, AutoMode, EncType, Chan);

	return 0;
}


#define timercmp(a, b, CMP)                                                  \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((a)->tv_sec CMP (b)->tv_sec))

#define timersub(a, b, result)                                               \
do {                                                                        \
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
	if ((result)->tv_usec < 0) {                                              \
		--(result)->tv_sec;                                                     \
		(result)->tv_usec += 1000000;                                           \
	}                                                                         \
} while (0)


//大于等于base时间 基准时间是ms 返回0 否则返回 -1
static int airkiss_timerout(struct timeval *last, struct timeval *current, struct timeval *timeout)
{
	//秒
	struct timeval tm;

	timersub(current, last, &tm);
	
	if (timercmp(&tm, timeout, >=)) {
		//debug_print("sec:%d usec:%d\n", tm.tv_sec, tm.tv_usec);
		return 0;
	}
	
	return -1;
}

#define PID_FILE "/var/run/airkiss.pid"

int lock_file(int fd)
{
	struct flock fl;
	
	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	
	return (fcntl(fd, F_SETLK, &fl));
}

int airkiss_runnind(void)
{
	int fd;
	char buf[16];
	debug_print("open %s\n", PID_FILE);
  
	fd = open(PID_FILE, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		debug_print("open %s fail\n", PID_FILE);
		exit(1);
	}
	
	if (lock_file(fd) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			close(fd);
			debug_print("alone runnind\n");
			return -1;
		}
		
		printf("can't lock %s: %s\n", PID_FILE, strerror(errno));
	}
	
	ftruncate(fd, 0);  //设置文件的大小为0
	
	sprintf(buf, "%ld", (long)getpid());
	
	write(fd, buf, strlen(buf) + 1);

	close(fd);
	debug_print("close %s\n", PID_FILE);
	
	
	return 0;
}

#if 0
struct ap_content {
	char ssid[186];
	unsigned char channel;
	char bssid[16];
	char Sec[23];
	char *w_mod;
} ;

struct ap_content AP_CONTENT_ARRAY[64];



/*****************************************************************
	函数名称 ： scan_task
	函数功能 ： AP扫描任务， 存放扫描到的ap 用以快速连接
*****************************************************************/
void *scan_task(void * arg)
{
	FILE *pp;
	char cmd[256], *ptr, wif[5];
	char channel[4], ssid[186], bssid[20], security[23];
	char signal[9], mode[7], ext_ch[7], net_type[3];
	int i, space_start;

	int j=0;	
	int ret = 0;

	(void)arg;

	strcpy(wif, "ra0");
	do_system("iwpriv %s set SiteSurvey=1", wif);
	
	sleep(2); // for get the SCAN result. (2G + 5G may enough for 5 seconds)
	
	sprintf(cmd, "iwpriv %s get_site_survey", wif);
	if ( !(pp = popen(cmd, "r")) ) {
		debug_print("execute get_site_survey fail!");
		return -1;
	}

	memset(cmd, 0, sizeof(cmd));
	fgets(cmd, sizeof(cmd), pp);	//前两行非数据
	fgets(cmd, sizeof(cmd), pp);
	
	while (fgets(cmd, sizeof(cmd), pp)) {
		if (strlen(cmd) < 4)
			break;
		
		ptr = cmd;
		sscanf(ptr, "%s ", channel);
		
		ptr += 37;
		sscanf(ptr, "%s %s %s %s %s %s", bssid, security, signal, mode, ext_ch, net_type);
		
		ptr = cmd+4;
		
		i = 0;
		while (i < 33) {
			if ((ptr[i] == ' ') && (i == 0 || ptr[i-1] != ' '))
				space_start = i;
			i++;
		}
		
		ptr[space_start] = '\0';
		strcpy(bssid, cmd+4);

		if ( !strcmp(bssid, air_ssid) && (atoi(channel) == air_channel) ) {
			debug_print("-----%s %s %s %s %s %s-----\n", bssid, security, signal, mode, ext_ch, net_type);
			
			if( (strstr(security, "none")) || (strstr(security, "NONE")) || (strstr(security, "OPEN")) ) {
				
				//strcpy(ap_Enc,"none");
				strcpy(AutoMode, "OPEN");
				strcpy(EncType, "NONE");
			} else if ((strstr(security,"WEP"))) {
			
				//strcpy(ap_Enc,"wep");
				strcpy(AutoMode, "SHARED");
				strcpy(EncType, "WEP");
				
				//nvram_bufset(RT2860_NVRAM,"ApCliDefaultKeyID","1");
				//nvram_bufset(RT2860_NVRAM,"ApCliKey1Type","1");
				
			} else if ((strstr(security,"WPA2"))) {
				
				if ((strstr(security,"TKIP"))) {
					
					//strcpy(ap_Enc,"wpa2_tkip");
					strcpy(AutoMode, "WPA2PSK");
					strcpy(EncType, "TKIP");
				} else {
				
					//strcpy(ap_Enc,"wpa2_aes");
					strcpy(AutoMode, "WPA2PSK");
					strcpy(EncType, "AES");
				}
			
			} else if ((strstr(security,"WPA"))) {
			
				if ((strstr(security,"TKIP"))) {
					
					//strcpy(ap_Enc,"wpa_tkip");
					strcpy(AutoMode, "WPAPSK");
					strcpy(EncType, "TKIP");
				} else {
				
					//strcpy(ap_Enc,"wpa_aes");
					strcpy(AutoMode, "WPAPSK");
					strcpy(EncType, "AES");
				}
			} else{
				//strcpy(ap_Enc,"wpa_aes");
				strcpy(AutoMode, "WPA2PSK");
				strcpy(EncType, "AES");
			}
		
			return 0;
		}

	}
	
	pclose(pp);

	return -1;
}
#endif

int main(int argc, char* argv[])
{
    int length;
    RX_PKT mp;
    int ret= -1;
    int i;
    int socket_id;
    unsigned char data[RX_BUF_SIZE];
	int locked = 0;
	pthread_t scan_tid;
	
	struct timeval select_timeout, locked_timeout;
	struct timeval airkiss_min_time = {0, 100000};
	struct timeval airkiss_max_time = {10, 0};

	struct timeval time1 = {0, 0};
	struct timeval time2 = {0, 0};

	if (airkiss_runnind() ) {
		return -1;
	}
	
    signal_handle();

    config.memcpy = memcpy;
    config.memset = memset;
    config.memcmp = memcmp;
    config.printf = printf;

    printf("airkiss version : %s\n", airkiss_version());
	
    if( airkiss_init(&akcontext, &config) != 0) {
        debug_print("airkiss init fail\n");
        return -1;
    }

	miscellaneous_mode_enable();

#if 0
	pthread_create(&scan_tid, NULL, scan_task, NULL);
	(void)pthread_detach(scan_tid);
#endif

    socket_id = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ECONET+1));
    if (socket_id < 0)  {
        debug_print("open socket error. opt SOCK_RAW err:%d\n", errno);
        return -1;
    }

	//使用新的信道切换方式
	gettimeofday(&time1, NULL);
    
    for (;;) {
        fd_set read;
        int err;

		FD_ZERO(&read);
		FD_SET(socket_id, &read);

		select_timeout.tv_sec = 0;
		select_timeout.tv_usec = 100*1000;

        err = select(socket_id+1, &read, NULL, NULL, &select_timeout) ;
        if (err < 0) {
			if (errno != EINTR) {
				debug_print("select failed. err=%d and return\n", errno);
				break;
			}
			
			errno = 0;
			continue;
        }
		
		if (err == 0) {
			//timeout
			goto timeout_proc;
		}
		
        if (FD_ISSET(socket_id, &read)) {
            ret = recv(socket_id, data, RX_BUF_SIZE, 0);

            if (ret <= 0) {
                continue;
            } else {

				//hexdump(data, ret);
                ret = airkiss_recv(&akcontext, data+22, ret-22);
				
                if ( AIRKISS_STATUS_CHANNEL_LOCKED == ret) {
					
					debug_print("airkiss_recv  AIRKISS_STATUS_CHANNEL_LOCKED %d\n", ch_lst[ch_index]);
					gettimeofday(&locked_timeout, NULL);
					
					locked = 1;
					
                } else if (AIRKISS_STATUS_COMPLETE == ret) {
					debug_print("airkiss_recv  AIRKISS_STATUS_COMPLETE\n");

                    if (airkiss_get_result(&akcontext , &ak_result) < 0) {
                        debug_print("airkiss get result fail\n");
                        break;
                    } else {
						
                        debug_print("result ok!ssid is %s , key is %s\n" , ak_result.ssid , ak_result.pwd);
						
						ret = config_wifi(ak_result.ssid, ak_result.pwd, ch_lst[ch_index]);
						if (0 == ret) {
							//do_system("init_system readpenrestart");

							for (i = 0; i < 30; i++) {
								if (get_ap_linked) {
									get_ap_linked = 0;
									notify_webchat(ak_result.random);
									break;
								}
								sleep(1);
							}
							break;
						} 
						
						//重扫描
						locked = 0;
						time1 = time2;
						airkiss_init(&akcontext, &config);
						debug_print("airkiss config wifi fail UnLock\n");
						continue;
                    }
                }  else {
					//debug_print("airkiss recv :%d channel:%d\n", ret, ch_lst[ch_index]);
				}
            }
        }

timeout_proc:
		gettimeofday(&time2, NULL);

		if (!locked) {
			if ( 0 == airkiss_timerout(&time1, &time2, &airkiss_min_time)) {
				time_callback();
				time1 = time2;
				airkiss_change_channel(&akcontext);
			}
			
		} else {
			if (0 == airkiss_timerout(&locked_timeout, &time2, &airkiss_max_time) ) {
				locked = 0;
				time1 = time2;
				airkiss_init(&akcontext, &config);
				debug_print("airkiss timeout UnLock\n");
			}
		}
		
    }

    close(socket_id);		

	miscellaneous_mode_disable();

    return 0;
}
