#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#define BUF_LEN		0x80

#define min(x,y) ({ 			\
		typeof(x) _x = (x);	\
		typeof(y) _y = (y);	\
		(void) (&_x == &_y);	\
		_x < _y ? _x : _y; })

static uint32_t fill_data = 1;

static pthread_mutex_t  mutex_lock = PTHREAD_MUTEX_INITIALIZER;

struct buff_str{
	char 	*addr;
	struct buff_str *next_buf_addr;
	uint32_t read_enable;
	uint32_t write_enable;
	uint32_t length;
	uint32_t offset;
};

struct pingpong_buffer {
	struct buff_str buf1;
	struct buff_str buf2;
	struct buff_str *current_read;
	int read_switch;

	struct buff_str *current_write;
	int write_switch;
};

void print_mem(void * addr, uint32_t count, uint32_t size)
{
	int i;
	uint8_t * addr8 = addr;
	uint16_t * addr16 = addr;
	uint32_t * addr32 = addr;
	uint32_t g_paddr;
	
	g_paddr = (uint32_t)addr;

	switch (size)
	{
	case 1:
		for (i = 0; i < count; i++) {
			if ( (i % 16) == 0 )
				printf("\n0x%08X: ", g_paddr);
			printf(" %02X", addr8[i]);
			g_paddr++;
		}
		break;
	case 2:
		for (i = 0; i < count; i++) {
			if ( (i % 8) == 0 )
				printf("\n0x%08X: ", g_paddr);
			printf(" %04X", addr16[i]);
			g_paddr += 2;
		}
		break;
	case 4:
		for (i = 0; i < count; i++) {
			if ( (i % 4) == 0 )
				printf("\n0x%08X: ", g_paddr);
			printf(" %08X", addr32[i]);
			g_paddr += 4;
		}
		break;
	default:
		printf("error value!\n");
		break;
	}
	printf("\n\n");
}

/* return valule: bytes have read, or 0 if not read enable */ 
uint32_t read_from_pingpong_buf(struct pingpong_buffer *pp_buf, const uint32_t count)
{
	uint32_t ret = 0;
	uint32_t len;
	
	struct buff_str *buf;

	if (pp_buf->read_switch) {
		pp_buf->current_read = pp_buf->current_read->next_buf_addr;		
		pp_buf->read_switch = 0;
	}

	buf = pp_buf->current_read;

	pthread_mutex_lock(&mutex_lock);
	if(!buf->read_enable) {
		pthread_mutex_unlock(&mutex_lock);
		return 0;
	}
	pthread_mutex_unlock(&mutex_lock);

	len = min(count, buf->length - buf->offset);

	/* instead read() for test */
	print_mem(buf->addr, len, 1);

	ret += len;
	buf->offset += ret;
	
	pthread_mutex_lock(&mutex_lock);
	/* get to the buffer end, switch to next buffer */
	if(buf->offset == buf->length) { 
		buf->read_enable = 0;
		buf->write_enable = 1;	
		buf->offset = 0;
		pp_buf->read_switch = 1;
	}
	pthread_mutex_unlock(&mutex_lock);

	return ret;
}


uint32_t write_to_pingpong_buf(struct pingpong_buffer *pp_buf, const uint32_t count)
{
	struct buff_str *buf;

	if (pp_buf->write_switch) {
		pp_buf->current_write = pp_buf->current_write->next_buf_addr;		
		pp_buf->write_switch = 0;
	}

	buf = pp_buf->current_write;
	
	pthread_mutex_lock(&mutex_lock);
	if(!buf->write_enable) {
		pthread_mutex_unlock(&mutex_lock);
		return 0;
	}
	pthread_mutex_unlock(&mutex_lock);

	/* use memset instead write operations for test */
	memset(buf->addr, fill_data, BUF_LEN);
	fill_data++;

	/* when write finished, enable write */
	pthread_mutex_lock(&mutex_lock);
	buf->read_enable = 1;
	buf->write_enable = 0;	
	pp_buf->write_switch = 1;
	pthread_mutex_unlock(&mutex_lock);

	return BUF_LEN;
}

void * pingpong_read(void *arg)
{
	uint32_t ret;
	struct pingpong_buffer *pp_buf; 

	pp_buf = (struct pingpong_buffer *)arg;

	while (1) {
		printf("\n******************** read ************************\n");
		ret = read_from_pingpong_buf(pp_buf, BUF_LEN);
		if (!ret) {
			printf("read wait ......\n");
			sleep(1);
		}
	}
}

void * pingpong_write(void *arg)
{
	uint32_t ret;
	struct pingpong_buffer *pp_buf; 

	pp_buf = (struct pingpong_buffer *)arg;

	while (1) {
		printf("\n******************** write ************************\n");
		ret = write_to_pingpong_buf(pp_buf, BUF_LEN);	
		if (!ret) {
			printf("write wait ......\n");
			sleep(1);
		}
	}
}

int pingpong_init(struct pingpong_buffer *pp_buf)
{
	char *mem1, *mem2;
	struct buff_str *buf1, *buf2;

	buf1 = &pp_buf->buf1;
	buf2 = &pp_buf->buf2;

	mem1 = malloc(BUF_LEN);
	if(mem1 == NULL) {
		perror("pingpong_init()");
		return -ENOMEM;
	}

	mem2 = malloc(BUF_LEN);
	if(mem2 == NULL) {
		perror("pingpong_init()");
		free(mem1);
		return -ENOMEM;
	}

	buf1->addr = mem1;
	buf1->next_buf_addr = buf2;
	buf1->read_enable = 0;
	buf1->write_enable = 1;	
	buf1->length = BUF_LEN;
	buf1->offset = 0;


	buf2->addr = mem2;
	buf2->next_buf_addr = buf1;
	buf2->read_enable = 0;
	buf2->write_enable = 1;	
	buf2->length = BUF_LEN;
	buf2->offset = 0;

	pp_buf->current_read = buf1;
	pp_buf->read_switch = 0;
	pp_buf->current_write = buf1;
	pp_buf->write_switch = 0;

	return 0;
}

void pingping_free(struct pingpong_buffer *pp_buf)
{
	if (pp_buf->buf1.addr) {
		free(pp_buf->buf1.addr);
		pp_buf->buf1.addr = NULL;
		pp_buf->buf1.next_buf_addr = NULL;
	}

	if (pp_buf->buf2.addr) {
		free(pp_buf->buf2.addr);
		pp_buf->buf2.addr = NULL;
		pp_buf->buf2.next_buf_addr = NULL;
	}
}

int main()
{
	int err;
	pthread_t read_pid, write_pid;
	struct pingpong_buffer pp_buf; 

	err = pingpong_init(&pp_buf);
	if (err < 0) {
		exit(1);
	}

	err = pthread_create(&read_pid, NULL, pingpong_read, &pp_buf);
	if (err) { 
		perror("pthread_create()");
		pingping_free(&pp_buf);
		exit(1);
	}
	err = pthread_create(&write_pid, NULL, pingpong_write, &pp_buf);
	if (err) {
		perror("pthread_create()");
		pthread_cancel(read_pid);
		pingping_free(&pp_buf);
		exit(1);
	}

	pthread_join(read_pid, NULL);
	pthread_join(write_pid, NULL);

	pingping_free(&pp_buf);

	exit(0);
}
