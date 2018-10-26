#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdlib.h>     
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include "cJSON.h"

#define METHOD_OFFSET 5
#define URL_TOKEN "url="
#define DIR_TOKEN "dst_dir="
#define END_TOKEN "flag=end"
#define ECHO_TOKEN "HTTP/1.0 200 ok\n\n"
#define FILENAME_TOKEN "filename="
#define OFFSET_TOKEN "org_offset="
#define READ_BLOCK_LEN_TOKEN "len="

//需要MT7628保证只有一个USB口， 另外， 需要保证一定是挂载到/media/sda1上
#define USB_MOUNT_PATH "/media/sda1"	//点读笔TF卡的挂载路径
#define READ_PEN_DEVICE "/dev/sda1"

#define DIR_MODE 0666

#ifdef DEBUG
#define http_log(fmt, ...) \
do {\
	printf(fmt, ##__VA_ARGS__);\
} while (0)
#else
#define http_log(fmt, ...)
#endif

pthread_mutex_t dir_mutex = PTHREAD_MUTEX_INITIALIZER;

char *opmethod[5] = { "download", "listfile", "readblock", "writeblock", "rename" };

int readblock(char *filepath, char *mount_point, unsigned long int offset, unsigned long int length, char *read_result)
{	
	FILE *fp = NULL;
	long f_len;
	unsigned char *data = NULL;
	int i = 0;	
	char realpathp[256];
	
	//拼接文件路径
	strcpy(realpathp, mount_point);
	strcat(realpathp, "/");
	strcat(realpathp, filepath);

	fp = fopen(realpathp, "rb");
	if (NULL == fp) {
		http_log("Open file %s failed !!!\n", realpathp);
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	
	f_len = ftell(fp);
		
	if (f_len < offset) {
		http_log("offset is invalid!!!\n");
		fclose(fp);
		return -1;
	}

	if (offset + length > f_len) {
		http_log("length is invalid.\n");
		fclose(fp);
		return -1;
	}
	
	data = (unsigned char *)malloc(length);
	if (NULL == data) {
		http_log("malloc failed length:%ld \n", length);
		fclose(fp);
		return -1;
	}
	
	fseek(fp, offset, SEEK_SET);
	
	http_log("datasize : %ld\n", length);
	
	(void)fread(data, length, 1, fp);
		
	for(i = 0; i < length; i++) {
		sprintf(&(read_result[i*2]), "%02x", data[i]);
	}
	
	fclose(fp);
	free(data);

	return 0;
}

/***************************
检查点读笔设备是否已经连接到USB且 已经挂载到/media/sda1
/dev/sda1 /media/sda1 vfat rw,relatime,fmask=0000,dmask=0000,allow_utime=0022,codepage=cp437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro 0 0
***************************/
int CheckReadPen(char *point, char *type)
{
	FILE * fp = NULL;
	char buf[1024];
	char *ptr;
	char *mount_point = NULL;
	char *file_system_type = NULL;

	fp = fopen("/proc/mounts", "r");

	while (1) { 
		ptr = fgets(buf, 1024, fp);
		if (NULL == ptr) {
			break;
		}
		http_log("Debug mount %s\n", ptr);
		if (NULL != strstr(ptr, READ_PEN_DEVICE)) {
			//1. 获取挂载点
			mount_point = ptr + strlen(READ_PEN_DEVICE)+1;
			ptr = strchr(mount_point, ' ');
			*ptr = '\0';
			http_log("mount point :%s\n", mount_point);
			//2. 获取挂载文件系统类型
			file_system_type = mount_point + strlen(mount_point) + 1;
			ptr = strchr(file_system_type, ' ');
			*ptr = '\0';
			http_log("file system type:%s\n", file_system_type);
			break;
		}
	}

	fclose(fp);
	
	//http_log("Check ReadPen Device:%d\n", errno);

	if (NULL == mount_point) {
		return -1;
	}
	
	strcpy(point, mount_point);
	strcpy(type, file_system_type);

	return 0;
}

int download_parse(char *getbuf, char **url, char **dir, char **jquery)
{
	char *ptr;
	
	if (ptr = strstr(getbuf, URL_TOKEN) ) {
		*url = ptr + strlen(URL_TOKEN);
	} else {
		http_log("download url not exist.\n");
		goto fail;
	}

	if (ptr = strchr(*url, '&')) {
		*ptr = '\0';//截取需要下载的url
	} else {
		http_log("download url end not exist .\n");
		goto fail;
	}

	if (ptr = strstr(*url+strlen(*url)+1, DIR_TOKEN)) {
		*dir = ptr + strlen(DIR_TOKEN);
	} else {
		http_log("download dir not exit.\n");
		goto fail;
	}
	
	if (ptr = strchr(*dir, '&')) {	//从左向右找& 找到&后改为'\0'
		*ptr = '\0';//截取需要下载的url
	} else {
		http_log("download dir str end not exist. \n");
		goto fail;
	}

	if (ptr = strstr(*dir+strlen(*dir)+1, END_TOKEN)) {
		*jquery = ptr + strlen(END_TOKEN) + 1;
	} else {
		http_log("GET END token not exit.\n");
		goto fail;
	}
	
	return 0;
fail:
	return -1;
}


/**********************************************************
函数名称：list_file_parse
函数功能：解析listfile方法\			
函数入参：getbuf: http://10.10.10.254:10008/listfile?dst_dir=/media&flag=end
函数返回值：0 OK
			1 FAIL
			dir 返回解析得到的目录字符串
			jquery 返回解析得到的jquery字符串
**********************************************************/
int list_file_parse(char *getbuf, char **dir, char **jquery)
{
	char *ptr;
	
	if (ptr = strstr(getbuf, DIR_TOKEN)) {
		*dir = ptr + strlen(DIR_TOKEN);
	} else {
		http_log("download dir not exit.\n");
		goto fail;
	}
	
	if (ptr = strchr(*dir, '&')) {	//从左向右找& 找到&后改为'\0'
		*ptr = '\0';//截取需要下载的url
	} else {
		http_log("download dir str end not exist. \n");
		goto fail;
	}

	if (ptr = strstr(*dir+strlen(*dir)+1, END_TOKEN)) {
		*jquery = ptr + strlen(END_TOKEN) + 1;
	} else {
		http_log("GET END token not exit.\n");
		goto fail;
	}
	
	return 0;
fail:
	return -1;
}



/**********************************************************
函数名称：read_block_parse
函数功能：解析read_block方法\			
函数入参：getbuf: http://10.10.10.254:10008/readblock?filename=/DICT/000.dab&org_offset=99&len=20&flag=end
函数返回值：0 OK
			1 FAIL
			dir 返回解析得到的目录字符串
			jquery 返回解析得到的jquery字符串
**********************************************************/
int read_block_parse(char *getbuf, char **filename, char **offset, char **length, char **jquery)
{
	char *ptr;
	
	if (ptr = strstr(getbuf, FILENAME_TOKEN)) {
		*filename = ptr + strlen(FILENAME_TOKEN);
	} else {
		http_log("download dir not exit.\n");
		goto fail;
	}
	
	if (ptr = strchr(*filename, '&')) {	//从左向右找& 找到&后改为'\0'
		*ptr = '\0';//截取filename字符串
	} else {
		http_log("readblock filename not exist. \n");
		goto fail;
	}

	if (ptr = strstr(*filename+strlen(*filename)+1, OFFSET_TOKEN)) {
		*offset = ptr + strlen(OFFSET_TOKEN);
	} else {
		http_log("readblock offset not exit.\n");
		goto fail;
	}
	
	if (ptr = strchr(*offset, '&')) {	//从左向右找& 找到&后改为'\0'
		*ptr = '\0';//截取offset字符串
	} else {
		http_log("download dir str end not exist. \n");
		goto fail;
	}

	if (ptr = strstr(*offset+strlen(*offset)+1, READ_BLOCK_LEN_TOKEN)) {
		*length = ptr + strlen(READ_BLOCK_LEN_TOKEN);
	} else {
		http_log("readblock offset not exit.\n");
		goto fail;
	}
	
	if (ptr = strchr(*length, '&')) {	//从左向右找& 找到&后改为'\0'
		*ptr = '\0';//截取offset字符串
	} else {
		http_log("download dir str end not exist. \n");
		goto fail;
	}

	if (ptr = strstr(*length+strlen(*length)+1, END_TOKEN)) {
		*jquery = ptr + strlen(END_TOKEN) + 1;
	} else {
		http_log("GET END token not exit.\n");
		goto fail;
	}
	
	return 0;
fail:
	return -1;
}

int check_dir(char *dir, char *mount_point)
{
	int ret;
	char *ptr;
	unsigned int offset = 1;	//不解析 根
	
	char realpathp[256];
	//拼接目录路径
	//strcpy(realpathp, USB_MOUNT_PATH);	//使用动态获取的路径 
	strcpy(realpathp, mount_point);
	strcat(realpathp, "/");
	strcat(realpathp, dir);

	do  {
		ptr = strchr(realpathp+offset, '/');
		if (ptr != NULL) {
			*ptr = '\0';
		} 
		
		pthread_mutex_lock(&dir_mutex);
		if (access(realpathp, F_OK) != 0 ) {	//查看目录结构是否存在
			errno = 0;
			
			ret = mkdir(realpathp, DIR_MODE);				
			
			if (ret < 0 ) {
				http_log("create %s dir failed errno:%d\n", realpathp, errno);
				break;
			}
		} 
		pthread_mutex_unlock(&dir_mutex);

		if (ptr) {
			*ptr = '/'; //恢复/
			offset += ptr-realpathp+1;
		} 
	}while (ptr);

	return 0;
fail:
	return -1;
}

int startup(void)
{
	int sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock < 0)
	{   
		exit(1);//退出进程
	}   

	int opt = 1;
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(10008); // 指定固定端口

	int ret = bind(sock,(struct sockaddr *)&local,sizeof(local));
	if( ret < 0 ) 
	{   
		exit(2);
	}   

	if( listen(sock,5) < 0 ) 
	{   
		exit(3);
	}   
	return sock;
}

char *fname_to_json(cJSON *json, char *directory, char *mount_point)
{
	int i = 0, ret;
	int len = 0;
	struct stat st;
	cJSON *result = cJSON_CreateObject();
	DIR    *dir;
	struct dirent    *ptr;
	char *json_ptr = NULL;
#define FILEPATH_LENGTH 256
	char realpathp[FILEPATH_LENGTH];
	
	
	strcpy(realpathp, mount_point);
	strcat(realpathp, "/");
	strcat(realpathp, directory);
	len = strlen(realpathp);

	dir = opendir(realpathp);
	if (dir) {
		while((ptr = readdir(dir)) != NULL) {
						
			if (ptr->d_name[0] == '.') {
				continue;
			}
			strcat(realpathp, "/");
			strcat(realpathp, ptr->d_name);
			
			ret = lstat(realpathp, &st);
			http_log("File:%s lstat:%d\n", realpathp, ret);
			
			if (S_ISDIR(st.st_mode)) {	//递归
				cJSON_AddStringToObject(result, ptr->d_name, "1");
			} else { 
				cJSON_AddStringToObject(result, ptr->d_name, "0");
			}
			memset(&realpathp[len], 0, FILEPATH_LENGTH - len);
		}
		
		cJSON_AddItemToObject(json, "result", result);
				
		closedir(dir);
	}

	return json_ptr;
}

//create a key-value pair

int test_create_json()
{
	cJSON * json = cJSON_CreateObject();
	cJSON *provinceArray = cJSON_CreateArray();
	cJSON *heilongjiang = cJSON_CreateObject();
	cJSON *hljcities = cJSON_CreateObject();
	cJSON *hljcityArray = cJSON_CreateArray();
	cJSON *guangdong = cJSON_CreateObject();
	cJSON *gdcities = cJSON_CreateObject();
	cJSON *gdcityArray = cJSON_CreateArray();
	cJSON *taiwan = cJSON_CreateObject();
	cJSON *twcities = cJSON_CreateObject();
	cJSON *twcityArray = cJSON_CreateArray();
	cJSON *xinjiang = cJSON_CreateObject();
	cJSON *xjcities = cJSON_CreateObject();
	cJSON *xjcityArray = cJSON_CreateArray();
	cJSON_AddStringToObject(json, "name", "中国");
	cJSON_AddStringToObject(heilongjiang, "name", "黑龙江");
	cJSON_AddItemToArray(hljcityArray, cJSON_CreateString("哈尔滨"));
	cJSON_AddItemToArray(hljcityArray, cJSON_CreateString("大庆"));
	cJSON_AddItemToObject(hljcities, "city", hljcityArray);
	cJSON_AddItemToObject(heilongjiang, "cities", hljcities);
	cJSON_AddStringToObject(guangdong, "name", "广东");
	cJSON_AddItemToArray(gdcityArray, cJSON_CreateString("广州"));
	cJSON_AddItemToArray(gdcityArray, cJSON_CreateString("深圳"));
	cJSON_AddItemToArray(gdcityArray, cJSON_CreateString("珠海"));
	cJSON_AddItemToObject(gdcities, "city", gdcityArray);
	cJSON_AddItemToObject(guangdong, "cities", gdcities);
	cJSON_AddStringToObject(taiwan, "name", "台湾");
	cJSON_AddItemToArray(twcityArray, cJSON_CreateString("台北"));
	cJSON_AddItemToArray(twcityArray, cJSON_CreateString("高雄"));
	cJSON_AddItemToObject(twcities, "city", twcityArray);
	cJSON_AddItemToObject(taiwan, "cities", twcities);
	cJSON_AddStringToObject(xinjiang, "name", "新疆");
	cJSON_AddItemToArray(xjcityArray, cJSON_CreateString("乌鲁木齐"));
	cJSON_AddItemToObject(xjcities, "city", xjcityArray);
	cJSON_AddItemToObject(xinjiang, "cities", xjcities);
	cJSON_AddItemToArray(provinceArray, heilongjiang);
	cJSON_AddItemToArray(provinceArray, guangdong);
	cJSON_AddItemToArray(provinceArray, taiwan);
	cJSON_AddItemToArray(provinceArray, xinjiang);
	cJSON_AddItemToObject(json, "province", provinceArray);
	printf("test_create_json:%s\n", cJSON_Print(json));
	if ( NULL != json )
	{
		cJSON_Delete(json);
		json = NULL;
	}
	return 0;
}

int test_parse_json()
{
	const char *jsonStr = "{						\
		\"name\": \"中国\",						\
 		\"province\": [{						\
			\"name\": \"黑龙江\",					\
 			\"cities\": {						\
				\"city\": [\"哈尔滨\", \"大庆\"]		\
 			}							\
 		}, {								\
 			\"name\": \"广东\",					\
 			\"cities\": {						\
 				\"city\": [\"广州\", \"深圳\", \"珠海\"]	\
 			}							\
 		}, {								\
 			\"name\": \"台湾\",					\
 			\"cities\": {						\
 				\"city\": [\"台北\", \"高雄\"]			\
 			}							\
 		}, {								\
 			\"name\": \"新疆\",					\
 			\"cities\": {						\
 			\"city\": [\"乌鲁木齐\"]				\
 			}							\
 		}]								\
 	}";
	cJSON *json = cJSON_Parse(jsonStr);
	if ( NULL != json )
	{
		cJSON * temp = cJSON_GetObjectItem(json, "name");
		if ( NULL != temp )
			printf( "name : %s\n", temp->valuestring);
		temp = cJSON_GetObjectItem(json, "province");
		printf( "province : \n");
		if ( NULL != temp )
		{
			int i = 0;
			int icount = cJSON_GetArraySize(temp);
			for (; i < icount; ++i)
			{
				cJSON * province = cJSON_GetArrayItem(temp, i);
				if ( NULL != province)
				{
					cJSON * name = NULL;
					cJSON * cities = NULL;
					name = cJSON_GetObjectItem(province, "name");
					cities = cJSON_GetObjectItem(province, "cities");
					if ( NULL != name )
						printf("    name : %s\n", name->valuestring);
					printf("    cities : \n");
					if ( NULL != cities )
					{
						cJSON * city = cJSON_GetObjectItem(cities, "city");
						printf ("        city:");
						if ( NULL != city )
						{
							int j = 0;
							int jcount = cJSON_GetArraySize(city);
							for (; j < jcount; ++j)
							{
							cJSON *cityItem = cJSON_GetArrayItem(city, j);
								if ( NULL != cityItem )
									printf ("%s ", cityItem->valuestring);
							}
						}
						printf ("\n\n");
					}
				}
			}
		}
		cJSON_Delete(json);
		json = NULL;
	}
	return 0;
}

int str_to_cJSON(char *json_string, char *str_val)
{
	char * out=NULL;
	cJSON *root=cJSON_CreateObject();
	if (!root)	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}else{
		cJSON *item=cJSON_CreateString("Brett");
		cJSON_AddItemToObject(root,"firstName",item);
		out=cJSON_Print(root);
		printf("out2:%s\n",out);
		cJSON_Delete(root);
		if(out!=NULL)	{
		free(out);
		}
	}
	return 0;
}

int chr_int(char hex) 
{
    if (hex>='0' && hex <='9')
        return hex - '0';
    if (hex>='A' && hex <= 'F')
        return hex-'A'+10;
    if(hex>='a' && hex <= 'f')
        return hex-'a'+10;
    return -1;
}

int str_int(char *hex)
{
    return chr_int(hex[0]) * 16 + chr_int(hex[1]);
}

void list_directory(char *directory)
{
	DIR    *dir;
	struct    dirent    *ptr;

	dir = opendir(directory);

	while((ptr = readdir(dir)) != NULL)
		printf("d_name: %s\n", ptr->d_name);

	closedir(dir);
}

static  int asciistr_i(char *s)
{
	int i = 0;
	while (isdigit(*s)) {
		i = i * 10 + *(s++) - '0';
	}
	return i;
}


#if 0
void* handler_request(void * arg)
{
	char buf[4896];
	char cmd_buf[1024];
	char filename_buf[1024];
	
	int sock = (int)arg;
	int i = 0;
	int ret_buf_len = 0;
	char *ret_buf = NULL;
	
	int methodlen[5] = {8, 8, 8, 10, 6};
	char *p1, *p2;
	char *jquery;
	const char *callback = "callback";
	const char *flagend = "flag=end";
	char *ptr;

	http_log("Start Read HTTP Client.\n");
	
	ssize_t s = read(sock, buf,sizeof(buf)-1);	//读取客户端GET数据 
	if( s > 0 ) {
		buf[s] = 0;	//字符串形式
		//http_log(%s, buf);
		//check method
		
		//字符串形式
		//"GET /download?url=http://maiya-1256866573.cos.ap-guangzhou.myqcloud.com/000.dab&dst_dir=/media&flag=end
		/*
			00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
		 	G  E  T      /  d  o  w  n  l  o  a  d        
		                                                 p1
		                                                 
		*/
		if(0 == strncmp(buf, "GET", 3)) { //GET方法： GET  
		
			for(i = 0; i < 5; i++) {
				if(0== strncmp(buf + METHOD_OFFSET, opmethod[i], methodlen[i])) {
					http_log("method : %s\n", opmethod[i]);
					break;
				}
			}
		
		switch(i) {
			case 0: //download
				{

					http_parse();
					
					const char *urlstr="url";
					const char *dirstr="dst_dir";
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					unsigned char *dir_buf = NULL;					
					unsigned char *urlbuf =NULL;
					char cmdbuf[512]={0};
					int url_len=0;
					int dir_len=0;
					int i=0;	
					cJSON *json = cJSON_CreateObject();
					char *json_ptr=NULL;
					
					printf("download!!!\n");
					//解析客户端的字符串类似：http://10.10.10.254:10008/download?&url=http://maiya-1256866573.cos.ap-guangzhou.myqcloud.com/000.dab&dst_dir=/media&flag=end
                    //                                                   	     p2指向&字符位置
					p1 = buf + 6 + 8 + 1; //p1指向下载的url地址起始 
					
					p2  = strchr(p1, '&');	//找& 字符 p2
					
					url_len = p2 - p1 - strlen(urlstr); //url_len = p2-p1 
					
					urlbuf = malloc(url_len);
					if(!urlbuf) {
						printf("malloc  failed\n");
					}
					memset(urlbuf,0,url_len);
					
					snprintf(urlbuf, p2-p1-strlen(urlstr), (char *)p1+strlen(urlstr)+1);
					printf("\n urlbuf=%s\n",urlbuf);
					
					p1=buf+6+8+1+strlen(urlstr)+url_len+1;
					//printf("p1=%s\n",p1);
					
					p2  = strchr(p1,'&');
					dir_len = p2-p1-strlen(dirstr);
					printf("\n dir_len=%d\n",dir_len);
					
					dir_buf = malloc(dir_len);
					if(!dir_buf){
						printf("malloc  failed\n");
					}
					memset(dir_buf,0,dir_len);
					
					snprintf(dir_buf,p2-p1-strlen(dirstr),(char *)p1+strlen(dirstr)+1);
					printf("\n dir_buf=%s\n",dir_buf);	

					//get jQuery

					p1=buf+6+8+1+strlen(urlstr)+url_len+1+strlen(dirstr)+1+strlen(dir_buf)+1+strlen(flagend)+1;
					//printf("*****:%s\n",p1);	
					
					p2 = strchr(p1,'&');
					jquery = malloc(p2-p1+1-strlen(callback));						
					if(!jquery){
						printf("jquery malloc  failed\n");
					}

					memset(jquery,0,p2-p1+1-strlen(callback));

					snprintf(jquery,p2-p1+1-strlen(callback)-1,p1+strlen(callback)+1);
					//printf("jquery*****:%s\n",jquery);	

					
					memset(cmdbuf, 0, 512);
					sprintf(cmdbuf,"wget %s -P %s", urlbuf, dir_buf);

					system(cmdbuf);
					free(urlbuf);
					free(dir_buf);

					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					if ( NULL != json )
					{
						json_ptr = cJSON_Print(json);
						
						cJSON_Delete(json);
						json = NULL;

						printf("json string: %s; len = 0x%x \n", json_ptr,strlen(json_ptr));
					}

					ret_buf_len = strlen(echo_str)+strlen(jquery)+2+strlen(json_ptr);
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}

					memset(ret_buf,0,ret_buf_len);
					sprintf(ret_buf,"%s%s(%s)",echo_str,jquery,json_ptr);

					free(jquery);
					
				}
				break;
			case 1: //list file
				{
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					//system("ls /");
					//list_directory("/bin");
					p1 = buf+6+8+8;
					p2  = strchr(p1,'&');
					memset(filename_buf,0,sizeof(filename_buf));
					snprintf(filename_buf,p2-p1+1,(char *)p1);
					printf("\n filename_buf=%s\n",filename_buf);

					p1 = buf+6+8+8+strlen(filename_buf)+1+strlen(flagend)+1;
					p2 = strchr(p1,'&');
					jquery = malloc(p2-p1+1-strlen(callback));						
					if(!jquery){
						printf("jquery malloc  failed\n");
					}

					memset(jquery,0,p2-p1+1-strlen(callback));

					snprintf(jquery,p2-p1+1-strlen(callback)-1,p1+strlen(callback)+1);
					//printf("*****:%s\n",jquery);					


					
					p1 = NULL;
					p1 = fname_to_json(filename_buf);
					ret_buf_len = strlen(p1)+strlen(echo_str)+strlen(jquery)+2;
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}
					memset(ret_buf,0,ret_buf_len);
					sprintf(ret_buf,"%s%s(%s)",echo_str,jquery,p1);
					//printf("######:%s\n",ret_buf);
					free(jquery);
					test_create_json();
					//test_parse_json();
				}
				break;
			case 2: //read block and change data to ASCII string
				{
					int offset=0;
					char offset_buf[10]; 					
					int blocklen=0;	
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					const char *org_offset="org_offset";
					const char *lenstr = "len";
					char len_buf[10];
					int len = 0;
					FILE *fp = NULL;
					int f_len = 0;
					unsigned char *data = NULL;
					char *datatochar_p = NULL;
					int i=0;
					cJSON *json = cJSON_CreateObject();
					char *json_ptr=NULL;


					
					p1 = buf+6+10+8;
					p2  = strchr(p1,'&');
					memset(filename_buf,0,sizeof(filename_buf));
					snprintf(filename_buf,p2-p1+1,(char *)p1);
					printf("\n filename_buf=%s\n",filename_buf);
					memset(offset_buf,0,sizeof(offset_buf));
					p1 = buf+6+10+8+strlen(filename_buf)+1;
					p2  = strchr(p1,'&');
					snprintf(offset_buf,p2-p1-strlen(org_offset),p1+strlen(org_offset)+1);
					printf("\n offset_buf=%s\n",offset_buf);
					offset = asciistr_i(offset_buf);
					printf("\n offset=%d\n",offset);
					p1 = buf+6+10+8+strlen(filename_buf)+1+strlen(org_offset)+1+strlen(offset_buf)+1;
					printf("\np1=%s\n",p1);
					p2 = strchr(p1,'&');
					snprintf(len_buf,p2-p1-strlen(lenstr),p1+strlen(lenstr)+1);
					printf("\n len_buf=%s\n",len_buf);
					len = asciistr_i(len_buf);
					printf("\n len=%d\n",len);


					p1 = buf+6+10+8+strlen(filename_buf)+1+strlen(org_offset)+1+strlen(offset_buf)+1+strlen(lenstr)+4+strlen(flagend)+1;
					//printf("\n********:%s\n",p1);

					p2 = strchr(p1,'&');
					jquery = malloc(p2-p1+1-strlen(callback));						
					if(!jquery){
						printf("jquery malloc  failed\n");
					}

					memset(jquery,0,p2-p1+1-strlen(callback));

					snprintf(jquery,p2-p1+1-strlen(callback)-1,p1+strlen(callback)+1);
					//printf("@@@@@@@@:%s\n",jquery);					

					//read block
					fp=fopen(filename_buf,"rb" );
					if (!fp ) 
					{
						printf("Open file failed!!!\n");
						return 0;
					}

					fseek(fp, 0, SEEK_END);
					f_len = ftell(fp);
					printf("f_len=0x%x\n",f_len);
					if(f_len < offset){
						printf("offset is bigger than file length!!!\n");
						return 0;

					}
					data = (unsigned char *)malloc(len);
					if(!data){
						printf("malloc  failed\n");
					}
					fseek(fp,(unsigned long int)(offset), SEEK_SET);
					printf("datasize:%d\n",sizeof(data));
					//i= fread(data,sizeof(data), 1, fp);
					i= fread(data,len, 1, fp);
					printf("i=%x\n",i);
					
					

					for(i=1;i<len+1;i++){
						printf("%x",data[i-1]);
						if(i % 16 == 0)
							printf("\n");
					}
					printf("\n");

					


					
					fclose(fp);
					
					printf("i=%x\n",i-1);


					datatochar_p = (char *)malloc(len*2+1);
					memset(datatochar_p,0,len*2+1);
					for(i=0;i<len;i++){
						sprintf(&(datatochar_p[i*2]),"%02x",data[i]);
					}
					//printf("\ndatatochar_p=%s\n",datatochar_p);

					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					cJSON_AddStringToObject(json, "result", datatochar_p);
					if ( NULL != json )
					{
						json_ptr = cJSON_Print(json);
						
						cJSON_Delete(json);
						json = NULL;

						printf("json string: %s; len = 0x%x \n", json_ptr,strlen(json_ptr));
					}
					

					ret_buf_len =  strlen(echo_str)+strlen(jquery)+2+strlen(json_ptr);
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}

					memset(ret_buf,0,ret_buf_len);
		


					
					sprintf(ret_buf,"%s%s(%s)",echo_str,jquery,json_ptr);

					printf(">>>>>:%s\n",ret_buf);
	
					free(data);
					free(jquery);
					free(datatochar_p);
					
				
				}
				break;

			case 3: //write block
				{
					int offset=0;
					char offset_buf[10]; 					
					int blocklen=0;
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					const char *org_offset="org_offset";
					const char *lenstr = "len";
					const char *datastr = "data";
					char len_buf[10];
					
					int len = 0;
					FILE *fp = NULL;
					int f_len = 0;
					unsigned char *data = NULL;
					int i=0;
					unsigned char *recblockbuf =NULL;					
					cJSON *json = cJSON_CreateObject();
					char *json_ptr=NULL;

					
					printf("\n writeblock\n");
					p1 = buf+6+11+8;
					p2  = strchr(p1,'&');
					memset(filename_buf,0,sizeof(filename_buf));
					snprintf(filename_buf,p2-p1+1,(char *)p1);
					printf("\n filename_buf=%s\n",filename_buf);
					memset(offset_buf,0,sizeof(offset_buf));
					p1 = buf+6+11+8+strlen(filename_buf)+1;
					p2  = strchr(p1,'&');
					snprintf(offset_buf,p2-p1-strlen(org_offset),p1+strlen(org_offset)+1);
					printf("\n offset_buf=%s\n",offset_buf);
					offset = asciistr_i(offset_buf);
					printf("\n offset=%d\n",offset);
					p1 = buf+6+11+8+strlen(filename_buf)+1+strlen(org_offset)+1+strlen(offset_buf)+1;
					printf("\np1=%s\n",p1);
					p2 = strchr(p1,'&');
					snprintf(len_buf,p2-p1-strlen(lenstr),p1+strlen(lenstr)+1);
					printf("\n len_buf=%s\n",len_buf);
					len = asciistr_i(len_buf);
					printf("\n len=%d\n",len);

					p1 = buf+6+11+8+strlen(filename_buf)+1+strlen(org_offset)+1+strlen(offset_buf)+1+strlen(len_buf)+1+4;
					printf("\n p1=%s\n",p1);	
					p2 = strchr(p1,'&');
					
					recblockbuf = (unsigned char *)malloc(len+1);
					if(!recblockbuf){
						printf("malloc  failed\n");
					}
					memset(recblockbuf,0,len+1);
					snprintf(recblockbuf,p2-p1-strlen(datastr),p1+strlen(datastr)+1);
					printf("recblockbuf=%s\n",recblockbuf);

					//get jQuery
					p1 = buf+6+10+8+strlen(filename_buf)+1+strlen(org_offset)+1+strlen(offset_buf)+1+strlen(lenstr)+4+strlen(recblockbuf)+1+strlen(flagend)+1+6;
					//printf("\n********:%s\n",p1);

					p2 = strchr(p1,'&');
					jquery = malloc(p2-p1+1-strlen(callback));						
					if(!jquery){
						printf("jquery malloc  failed\n");
					}

					memset(jquery,0,p2-p1+1-strlen(callback));

					snprintf(jquery,p2-p1+1-strlen(callback)-1,p1+strlen(callback)+1);
					printf("\n********:%s\n",jquery);


					data = (unsigned char *)malloc(len+1);
					if(!data){
						printf("malloc  failed\n");
					}
					memset(data,0,len+1);
					for(i=0;i<len/2;i++){
						data[i] = str_int(&recblockbuf[i*2]);
					}

					free(recblockbuf);
					//write block
					fp=fopen(filename_buf,"rb+" );
					if (!fp ) 
					{
						printf("Open file failed!!!\n");
						return 0;
					}

					fseek(fp, 0, SEEK_END);
					f_len = ftell(fp);
					printf("f_len=0x%x\n",f_len);
					if(f_len < offset){
						printf("offset is bigger than file length!!!\n");
						return 0;

					}
					
					fseek(fp,(unsigned long int)(offset), SEEK_SET);
					
					printf("datasize:%d\n",sizeof(data));
					
					//i= fread(data,sizeof(data), 1, fp);
					i= fwrite(data,len/2, 1, fp);
					printf("i=%x\n",i);
			
					
					fclose(fp);

					free(data);
					printf("i=%x\n",i-1);

					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					if ( NULL != json )
					{
						json_ptr = cJSON_Print(json);
						
						cJSON_Delete(json);
						json = NULL;

						printf("json string: %s; len = 0x%x \n", json_ptr,strlen(json_ptr));
					}
					

					
					ret_buf_len = strlen(echo_str)+strlen(jquery)+2+strlen(json_ptr);
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}

					memset(ret_buf,0,ret_buf_len);
					sprintf(ret_buf,"%s%s(%s)",echo_str,jquery,json_ptr);
					free(jquery);
									
					
				}
				break;
			case 4: //rename
				{
					char src_filename_buf[1024];
					char dst_filename_buf[1024];
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					const char *changedname= "changedname";
					cJSON *json = cJSON_CreateObject();
					char *json_ptr=NULL;
					
					#if 1 
					p1 = buf+6+7+8;
					p2  = strchr(p1,'&');
					memset(src_filename_buf,0,sizeof(src_filename_buf));
					snprintf(src_filename_buf,p2-p1+1,(char *)p1);
					printf("\n src_filename_buf=%s\n",src_filename_buf);
					
					memset(dst_filename_buf,0,sizeof(dst_filename_buf));
					memset(filename_buf,0,sizeof(filename_buf));
					
					p1 = buf+6+7+8+strlen(src_filename_buf)+1;
					p2  = strchr(p1,'&');
					snprintf(filename_buf,p2-p1+1,(char *)p1);
					printf("\n filename_buf=%s\n",filename_buf);
					snprintf(dst_filename_buf,strlen(filename_buf)-11,filename_buf+12);
					printf("\n dst_filename_buf=%s\n",dst_filename_buf);

					//get jQuery
					p1 = buf+6+7+8+strlen(src_filename_buf)+1+strlen(changedname)+1+strlen(dst_filename_buf)+1+strlen(flagend)+1;
					//printf("\n********:%s\n",p1);
					
					p2 = strchr(p1,'&');
					jquery = malloc(p2-p1+1-strlen(callback));						
					if(!jquery){
						printf("jquery malloc  failed\n");
					}

					memset(jquery,0,p2-p1+1-strlen(callback));

					snprintf(jquery,p2-p1+1-strlen(callback)-1,p1+strlen(callback)+1);
					printf("\n********:%s\n",jquery);

					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					if ( NULL != json )
					{
						json_ptr = cJSON_Print(json);
						
						cJSON_Delete(json);
						json = NULL;

						printf("json string: %s; len = 0x%x \n", json_ptr,strlen(json_ptr));
					}
					
					memset(cmd_buf,0,sizeof(cmd_buf));
					sprintf(cmd_buf,"mv %s %s",src_filename_buf,dst_filename_buf);
					system(cmd_buf);	
					#endif
					
					ret_buf_len = strlen(echo_str)+strlen(jquery)+strlen(json_ptr);
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}
					memset(ret_buf,0,ret_buf_len);
					sprintf(ret_buf,"%s%s(%s)",echo_str,jquery,json_ptr);
					free(jquery);
				}
				break;
			default:
				{
					const char *echo_str = "HTTP/1.0 200 ok\n\n";
					//cJSON *json = cJSON_CreateObject();
					//char *json_ptr=NULL;
					


					
					ret_buf_len = strlen(echo_str);
					ret_buf=malloc(ret_buf_len);
					if(!ret_buf){
						printf("malloc  failed\n");
					}
					memset(ret_buf,0,ret_buf_len);
					sprintf(ret_buf,"%s",echo_str);	
				}
				break;
		}


		}
		
			



		//ret_buf_len=1024;
		//ret_buf=malloc(ret_buf_len);
		//if(!ret_buf){
		//	printf("malloc  failed\n");
		//}
		//memset(ret_buf,0,ret_buf_len);
		//sprintf(ret_buf,"http ok --->%s\n","123456789");


		
		//const char *echo_str = "HTTP/1.0 200 ok\n\n<html><h1>Welcome to my http server!</h1><html>\n";	
		//write(sock,echo_str,strlen(echo_str));
		printf("--->%s\n",ret_buf);
		write(sock,ret_buf,strlen(ret_buf));
		free(ret_buf);
	}
	close(sock);
}
#else
void* handler_request(void * arg)
{
	char buf[4096];
	char cmdbuf[1024];
	char *response = NULL;
	char mount_point[64];
	char file_system_type[16];
	
	int sock = (int)arg;
	int i = 0, ret;
	char *url = NULL, *dir = NULL;
	char *jquery = NULL;
	char *json_ptr = NULL;
	char *filename = NULL, *offset_str = NULL, *length_str = NULL, *read_result = NULL;
	char *endptr;
	long offset, length;

	char *device_status[] = {"true", "false"};
	cJSON *json = cJSON_CreateObject();
	
	http_log("Start Read HTTP Client.\n");
	
	ssize_t s = read(sock, buf,sizeof(buf)-1);	//读取客户端GET数据 
	if( s > 0 ) {
		buf[s] = 0;	//尾部补零 字符串形式
		http_log("%s", buf);
		
		//"GET /download?url=http://maiya-1256866573.cos.ap-guangzhou.myqcloud.com/000.dab&dst_dir=/media&flag=end
		if(0 == strncmp(buf, "GET", 3)) { //GET方法： GET  
		
			for(i = 0; i < 5; i++) {
				if(0== strncmp(buf + METHOD_OFFSET, opmethod[i], strlen(opmethod[i]))) {
					http_log("method : %s\n", opmethod[i]);
					break;
				}
			}
		
			switch (i) {
				case 0: //download
					{						
						ret = download_parse(buf, &url, &dir, &jquery);
						if (ret < 0) {
							http_log("Parse download Method Failed.\n");
							//制造一个jquery
							goto download_response;
						}

						http_log("url:\n%s\n", url);
						http_log("dir:\n%s\n", dir);
						http_log("jquery:\n%s\n", jquery);

						if (CheckReadPen(mount_point, file_system_type)) {
							http_log("ReadPen has not mounted to MT7628.\n");
							cJSON_AddStringToObject(json, "msg", "OK");
							cJSON_AddStringToObject(json, "status", "fail");
							goto download_response;
						}
						
						if (check_dir(dir, mount_point)) {
							http_log("DIR Failed.\n");
							cJSON_AddStringToObject(json, "msg", "OK");
							cJSON_AddStringToObject(json, "status", "fail");
							goto download_response;
						}

						sprintf(cmdbuf, "wget %s -P %s/%s", url, mount_point, dir);	//dir是U盘的相对路径
						system(cmdbuf);
						
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "true");
download_response:
						json_ptr = cJSON_Print(json);
						cJSON_Delete(json);
						json = NULL;

						#if 0
						strcpy(response, ECHO_TOKEN);
						strcat(response, jquery);
						strcat(response, "(");
						strcat(response, json_ptr);
						strcat(response, ")");
						#endif

					}
					break;
				case 1: //list file
					//http://192.168.163.130:10008/listfile?dst_dir=/media&flag=end
					ret = list_file_parse(buf, &dir, &jquery);
					if (ret < 0) {
						http_log("Parse list Method Failed.\n");
						break;
					}

					http_log("dir:\n%s\n", dir);
					http_log("jquery:\n%s\n", jquery);

					if (CheckReadPen(mount_point, file_system_type)) {
						http_log("ReadPen has not mounted to MT7628.\n");
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto list_response;
					}
					
					if (check_dir(dir, mount_point)) {
						http_log("DIR Failed.\n");
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto list_response;
					}
					
					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					
					json_ptr = fname_to_json(json, dir, mount_point);
					if (NULL == jquery) {
						http_log("List Dir Failed.\n ");
						break;
					}

list_response:
					json_ptr = cJSON_Print(json);
					cJSON_Delete(json);
					
					break;
				case 2: //read block and change data to ASCII string
					//http://192.168.163.130:10008/readblock?filename=/DICT/000.dab&org_offset=99&len=20&flag=end
					
					ret = read_block_parse(buf, &filename, &offset_str, &length_str, &jquery);
					if (ret < 0) {
						http_log("Parse list Method Failed.\n");
						break;
					}

					http_log("filename:\n%s\n", filename);
					http_log("offset:\n%s\n", offset_str);
					http_log("length:\n%s\n", length_str);
					http_log("jquery:\n%s\n", jquery);

					if (CheckReadPen(mount_point, file_system_type)) {
						http_log("ReadPen has not mounted to MT7628.\n");
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto readblock_response;
					}
					
					length = strtol(length_str, &endptr, 10);
					if (length == LONG_MIN || length == LONG_MAX || (NULL != endptr && endptr != length_str+strlen(length_str))) {
						http_log("str to long failed length:%p endptr:%p length:%ld\n", length_str, endptr, length);
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto readblock_response;
					}
					
					offset = strtol(offset_str, &endptr, 10);
					if (offset == LONG_MIN || offset == LONG_MAX || (NULL != endptr && endptr != offset_str+strlen(offset_str))) {
						http_log("str to long failed length:%p endptr:%p offset:%ld\n", length_str, endptr, offset);
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto readblock_response;
					}

					read_result = (char *)malloc(length * 2 + 1);
					memset(read_result, 0, length * 2 + 1);
					
					if (readblock(filename, mount_point, offset, length, read_result) ) {
						cJSON_AddStringToObject(json, "msg", "OK");
						cJSON_AddStringToObject(json, "status", "fail");
						goto readblock_response;
					}

					cJSON_AddStringToObject(json, "msg", "OK");
					cJSON_AddStringToObject(json, "status", "true");
					
					cJSON_AddStringToObject(json, "result", read_result);
readblock_response:

					json_ptr = cJSON_Print(json);

					cJSON_Delete(json);
					free(read_result);
					break;
				case 3: //write block
					break;
				case 4: //rename
					
					break;
				default:
					break;
			}
			
			http_log("json string: %s; len = 0x%lu \n", json_ptr, strlen(json_ptr));

			response = malloc(strlen(ECHO_TOKEN) + strlen(jquery) + strlen("(") + strlen(json_ptr) + strlen(")") + 1);

			//HTTP 响应
			strcpy(response, ECHO_TOKEN);
			strcat(response, jquery);
			strcat(response, "(");
			strcat(response, json_ptr);
			strcat(response, ")");
			
			http_log("--->\n%s\n", response);
			write(sock, response, strlen(response));
			
			free(response);
			free(json_ptr);
		}
		

	}
	close(sock);
}
#endif

int main()
{
	int listen_sock = startup();
	
	while(1) {
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
	
		int sock = accept(listen_sock, (struct sockaddr*)&client, &len);

		if(sock < 0) {
			continue;
		}
			
		pthread_t tid;
		
		pthread_create(&tid, NULL, handler_request, (void *)sock);
		(void)pthread_detach(tid);
	}
	
	return 0; 
}
