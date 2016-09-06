#include "config.h"
#include <assert.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>



#ifndef WIN32
#include <sys/select.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#else
#include "compat.h"
#include <windows.h>
#include <io.h>
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "hexdump.c"
#include "util.h"
#include "driver-btm-c5.h"
#include "sha2_c5.h"

#define id_string_len 34
#define AUTH_URL    "auth.minerlink.com"
#define PORT        "7000"

#define USE_IIC 1
#define TEMP_CALI 0
#define MID_OR_BOT 1


#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

//global various

// BOOL
bool opt_bitmain_new_cmd_type_vil = false;
bool status_error = false;
bool once_error = false;
bool iic_ok = false;
bool opt_bitmain_fan_ctrl = false;
bool gBegin_get_nonce = false;
bool update_temp =false;
bool stop_mining = false;

static bool need_send = true;

// CHAR
char displayed_rate[BITMAIN_MAX_CHAIN_NUM][16];
char * mac;
char hash_board_id_string[BITMAIN_MAX_CHAIN_NUM*id_string_len];
unsigned char hash_board_id[BITMAIN_MAX_CHAIN_NUM][12];

// INTEGERS
int fd;                                         // axi fpga
int fd_fpga_mem;                                // fpga memory
int fpga_version;
int pcb_version;
int last_temperature = 0;
int temp_highest = 0;
int opt_bitmain_fan_pwm = 0;
int opt_bitmain_c5_freq = 600;
int opt_bitmain_c5_voltage = 176;
int ADD_FREQ = 0;
int ADD_FREQ1 = 0;
int check_iic = 0;
int rate_error[BITMAIN_MAX_CHAIN_NUM] = {0};

unsigned int is_first_job = 0;
unsigned int *axi_fpga_addr = NULL;             // axi address
unsigned int *fpga_mem_addr = NULL;             // fpga memory address
unsigned int *nonce2_jobid_address = NULL;      // the value should be filled in NONCE2_AND_JOBID_STORE_ADDRESS
unsigned int *job_start_address_1 = NULL;       // the value should be filled in JOB_START_ADDRESS
unsigned int *job_start_address_2 = NULL;       // the value should be filled in JOB_START_ADDRESS

uint8_t de_voltage = 176;
uint8_t chain_voltage[BITMAIN_MAX_CHAIN_NUM] = {0};

// --------------------------------------------------------------
//      CRC16 check table
// --------------------------------------------------------------
const uint8_t chCRCHTalbe[] =                                 // CRC high byte table
        {
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                0x00, 0xC1, 0x81, 0x40
        };

const uint8_t chCRCLTalbe[] =                                 // CRC low byte table
        {
                0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7,
                0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E,
                0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09, 0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9,
                0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC,
                0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
                0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32,
                0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D,
                0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38,
                0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF,
                0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
                0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1,
                0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4,
                0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F, 0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB,
                0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA,
                0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
                0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0,
                0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97,
                0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C, 0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E,
                0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89,
                0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
                0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83,
                0x41, 0x81, 0x80, 0x40
        };


//crc

uint32_t given_id = 2;
uint32_t c_coinbase_padding = 0;
uint32_t c_merkles_num = 0;
uint32_t l_coinbase_padding = 0;
uint32_t l_merkles_num = 0;

uint64_t h = 0;
uint64_t rate[BITMAIN_MAX_CHAIN_NUM] = {0};


// VOID
void *gpio0_vaddr=NULL;

// pthread_mutex_t
pthread_mutex_t reg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t nonce_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t reg_read_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t iic_mutex = PTHREAD_MUTEX_INITIALIZER;

// Struct
struct thr_info *read_nonce_reg_id;                 // thread id for read nonce and register
struct thr_info *check_system_work_id;                  // thread id for check system
struct thr_info *read_temp_id;
struct thr_info *read_hash_rate;
struct thr_info *pic_heart_beat;
struct thr_info *change_voltage_to_old;
struct thr_info *send_mac_thr;
struct timeval tv_send_job = {0, 0};
struct nonce_content temp_nonce_buf[MAX_RETURNED_NONCE_NUM];
struct reg_content temp_reg_buf[MAX_RETURNED_NONCE_NUM];
struct nonce_buf nonce_read_out;
struct reg_buf reg_value_buf;
struct all_parameters *dev;


uint16_t CRC16(const uint8_t* p_data, uint16_t w_len)
{
    uint8_t chCRCHi = 0xFF; // CRC high byte initialize
    uint8_t chCRCLo = 0xFF; // CRC low byte initialize
    uint16_t wIndex = 0;    // CRC cycling index

    while (w_len--)
    {
        wIndex = chCRCLo ^ *p_data++;
        chCRCLo = chCRCHi ^ chCRCHTalbe[wIndex];
        chCRCHi = chCRCLTalbe[wIndex];
    }
    return ((chCRCHi << 8) | chCRCLo);
}

unsigned char CRC5(unsigned char *ptr, unsigned char len)
{
    unsigned char i, j, k;
    unsigned char crc = 0x1f;

    unsigned char crcin[5] = {1, 1, 1, 1, 1};
    unsigned char crcout[5] = {1, 1, 1, 1, 1};
    unsigned char din = 0;

    j = 0x80;
    k = 0;
    for (i = 0; i < len; i++)
    {
        if (*ptr & j)
        {
            din = 1;
        }
        else
        {
            din = 0;
        }
        crcout[0] = crcin[4] ^ din;
        crcout[1] = crcin[0];
        crcout[2] = crcin[1] ^ crcin[4] ^ din;
        crcout[3] = crcin[2];
        crcout[4] = crcin[3];

        j = j >> 1;
        k++;
        if (k == 8)
        {
            j = 0x80;
            k = 0;
            ptr++;
        }
        memcpy(crcin, crcout, 5);
    }
    crc = 0;
    if(crcin[4])
    {
        crc |= 0x10;
    }
    if(crcin[3])
    {
        crc |= 0x08;
    }
    if(crcin[2])
    {
        crc |= 0x04;
    }
    if(crcin[1])
    {
        crc |= 0x02;
    }
    if(crcin[0])
    {
        crc |= 0x01;
    }
    return crc;
}

// pic
unsigned int get_pic_iic()
{
    int ret = -1;
    ret = *(axi_fpga_addr + IIC_COMMAND);

    applog(LOG_DEBUG,"%s: IIC_COMMAND is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

unsigned char set_pic_iic(unsigned int data)
{
    unsigned int ret=0;
    unsigned char ret_data = 0;

    *((unsigned int *)(axi_fpga_addr + IIC_COMMAND)) = data & 0x7fffffff;
    applog(LOG_DEBUG,"%s: set IIC_COMMAND is 0x%x\n", __FUNCTION__, data & 0x7fffffff);

    while(1)
    {
        ret = get_pic_iic();
        if(ret & 0x80000000)
        {
            ret_data = (unsigned char)(ret & 0x000000ff);
            return ret_data;
        }
        else
        {
            applog(LOG_DEBUG,"%s: waiting write pic iic\n", __FUNCTION__);
            cgsleep_us(1000);
        }
    }
}

unsigned char write_pic_iic(bool read, bool reg_addr_valid, unsigned char reg_addr, unsigned char chain, unsigned char data)
{
    unsigned int value = 0x00000000;
    unsigned char ret = 0;

    if(read)
    {
        value |= IIC_READ;
    }

    if(reg_addr_valid)
    {
        value |= IIC_REG_ADDR_VALID;
        value |= IIC_REG_ADDR(reg_addr);
    }

    value |= IIC_ADDR_HIGH_4_BIT;

    value |= IIC_CHAIN_NUMBER(chain);

    value |= data;

    ret = set_pic_iic(value);

    return ret;
}

void send_pic_command(unsigned char chain)
{
    write_pic_iic(false, false, 0x0, chain, PIC_COMMAND_1);
    write_pic_iic(false, false, 0x0, chain, PIC_COMMAND_2);
}


void set_pic_iic_flash_addr_pointer(unsigned char chain, unsigned char addr_H, unsigned char addr_L)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, SET_PIC_FLASH_POINTER);
    write_pic_iic(false, false, 0x0, chain, addr_H);
    write_pic_iic(false, false, 0x0, chain, addr_L);
}

void send_data_to_pic_iic(unsigned char chain, unsigned char command, unsigned char *buf, unsigned char length)
{
    unsigned char i=0;

    write_pic_iic(false, false, 0x0, chain, command);
    for(i=0; i<length; i++)
    {
        write_pic_iic(false, false, 0x0, chain, *(buf + i));
    }
}

void get_data_from_pic_iic(unsigned char chain, unsigned char command, unsigned char *buf, unsigned char length)
{
    unsigned char i=0;

    write_pic_iic(false, false, 0x0, chain, command);
    for(i=0; i<length; i++)
    {
        *(buf + i) = write_pic_iic(true, false, 0x0, chain, 0);
    }
}

void send_data_to_pic_flash(unsigned char chain, unsigned char *buf)
{
    send_pic_command(chain);
    send_data_to_pic_iic(chain, SEND_DATA_TO_IIC, buf, 16);
}

void get_data_from_pic_flash(unsigned char chain, unsigned char *buf)
{
    send_pic_command(chain);
    get_data_from_pic_iic(chain, READ_DATA_FROM_IIC, buf, 16);
}

unsigned char erase_pic_flash(unsigned char chain)
{
    unsigned char ret=0xff;

    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, ERASE_IIC_FLASH);
    while(1)
    {
        cgsleep_us(3000);
        ret = write_pic_iic(true, false, 0x0, chain, 0);
        if(ret == 0x0)
        {
            return ret;
        }
    }
}

unsigned char erase_pic_flash_all(unsigned char chain)
{
    unsigned char ret=0xff;
    unsigned int i=0, erase_loop = 0;
    unsigned char start_addr_h = PIC_FLASH_POINTER_START_ADDRESS_H, start_addr_l = PIC_FLASH_POINTER_START_ADDRESS_L;
    unsigned char end_addr_h = PIC_FLASH_POINTER_END_ADDRESS_H, end_addr_l = PIC_FLASH_POINTER_END_ADDRESS_L;
    unsigned int pic_flash_length=0;

    set_pic_iic_flash_addr_pointer(chain, PIC_FLASH_POINTER_START_ADDRESS_H, PIC_FLASH_POINTER_START_ADDRESS_L);

    pic_flash_length = (((unsigned int)end_addr_h << 8) + end_addr_l) - (((unsigned int)start_addr_h << 8) + start_addr_l) + 1;
    erase_loop = pic_flash_length/PIC_FLASH_SECTOR_LENGTH;
    for(i=0; i<erase_loop; i++)
    {
        erase_pic_flash(chain);
    }
}

void set_temperature_offset_value(unsigned char chain, unsigned char *value)
{
    send_pic_command(chain);
    send_data_to_pic_iic(chain, WR_TEMP_OFFSET_VALUE, value, 8);
    cgsleep_ms(100000);
}

void get_temperature_offset_value(unsigned char chain, unsigned char *value)
{
    send_pic_command(chain);
    get_data_from_pic_iic(chain, RD_TEMP_OFFSET_VALUE, value, 8);
}

unsigned char write_data_into_pic_flash(unsigned char chain)
{
    unsigned char ret=0xff;

    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, WRITE_DATA_INTO_PIC);
    while(1)
    {
        cgsleep_us(10000);
        ret = write_pic_iic(true, false, 0x0, chain, 0);
        if(ret == 0x0)
        {
            return ret;
        }
    }
}

unsigned char jump_to_app_from_loader(unsigned char chain)
{
    unsigned char ret=0xff;

    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, JUMP_FROM_LOADER_TO_APP);
    cgsleep_us(100000);
}

unsigned char reset_iic_pic(unsigned char chain)
{
    unsigned char ret=0xff;

    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, RESET_PIC);
    cgsleep_us(100000);
}

void get_pic_iic_flash_addr_pointer(unsigned char chain, unsigned char *addr_H, unsigned char *addr_L)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, GET_PIC_FLASH_POINTER);
    *addr_H = write_pic_iic(true, false, 0x0, chain, 0);
    *addr_L = write_pic_iic(true, false, 0x0, chain, 0);
}

void set_pic_voltage(unsigned char chain, unsigned char voltage)
{
    send_pic_command(chain);
    applog(LOG_NOTICE,"%s voltage %u",__FUNCTION__,voltage);
    write_pic_iic(false, false, 0x0, chain, SET_VOLTAGE);
    write_pic_iic(false, false, 0x0, chain, voltage);
    cgsleep_us(100000);
}

unsigned char get_pic_voltage(unsigned char chain)
{
    unsigned char ret=0;
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, GET_VOLTAGE);
    ret = write_pic_iic(true, false, 0x0, chain, 0);
    applog(LOG_NOTICE,"%s: voltage = %d\n", __FUNCTION__, ret);
    return ret;
}


void set_voltage_setting_time(unsigned char chain, unsigned char *time)
{
    send_pic_command(chain);
    send_data_to_pic_iic(chain, SET_VOLTAGE_TIME, time, 6);
    cgsleep_us(100000);
}

void set_hash_board_id_number(unsigned char chain, unsigned char *id)
{
    send_pic_command(chain);
    send_data_to_pic_iic(chain, SET_HASH_BOARD_ID, id, 12);
    cgsleep_us(100000);
}

void get_hash_board_id_number(unsigned char chain, unsigned char *id)
{
    send_pic_command(chain);
    get_data_from_pic_iic(chain, GET_HASH_BOARD_ID, id, 12);
}

void write_host_MAC_and_time(unsigned char chain, unsigned char *buf)
{
    send_pic_command(chain);
    send_data_to_pic_iic(chain, SET_HOST_MAC_ADDRESS, buf, 12);
    cgsleep_us(100000);
}

void enable_pic_dc_dc(unsigned char chain)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, ENABLE_VOLTAGE);
    write_pic_iic(false, false, 0x0, chain, 1);
}

void enable_pic_dc_dc_all()
{
    unsigned char i;
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            enable_pic_dc_dc(i);
            cgsleep_ms(1);
        }
    }
}

void set_pic_voltage_all(int voltage)
{
    unsigned char i;
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            cgsleep_ms(100);
            jump_to_app_from_loader(i);
            cgsleep_ms(100);
            set_pic_voltage(i,voltage);
            cgsleep_ms(1);
        }
    }
}

void enable_pic_dac(unsigned char chain)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, ENABLE_VOLTAGE);
    write_pic_iic(false, false, 0x0, chain, 1);
}

void disable_pic_dac(unsigned char chain)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, ENABLE_VOLTAGE);
    write_pic_iic(false, false, 0x0, chain, 0);
}


void pic_heart_beat_each_chain(unsigned char chain)
{
    send_pic_command(chain);
    write_pic_iic(false, false, 0x0, chain, SEND_HEART_BEAT);
}

//FPGA related
int get_nonce2_and_job_id_store_address(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + NONCE2_AND_JOBID_STORE_ADDRESS));
    applog(LOG_DEBUG,"%s: NONCE2_AND_JOBID_STORE_ADDRESS is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_nonce2_and_job_id_store_address(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + NONCE2_AND_JOBID_STORE_ADDRESS)) = value;
    applog(LOG_DEBUG,"%s: set NONCE2_AND_JOBID_STORE_ADDRESS is 0x%x\n", __FUNCTION__, value);
    get_nonce2_and_job_id_store_address();
}

int get_job_start_address(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + JOB_START_ADDRESS));
    applog(LOG_DEBUG,"%s: JOB_START_ADDRESS is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_job_start_address(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + JOB_START_ADDRESS)) = value;
    applog(LOG_DEBUG,"%s: set JOB_START_ADDRESS is 0x%x\n", __FUNCTION__, value);
    get_job_start_address();
}

int get_QN_write_data_command(void)
{
    int ret = -1;
    ret = *((axi_fpga_addr + QN_WRITE_DATA_COMMAND));
    applog(LOG_DEBUG,"%s: QN_WRITE_DATA_COMMAND is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_QN_write_data_command(unsigned int value)
{
    *(axi_fpga_addr + QN_WRITE_DATA_COMMAND) = value;
    applog(LOG_DEBUG,"%s: set QN_WRITE_DATA_COMMAND is 0x%x\n", __FUNCTION__, value);
    get_QN_write_data_command();
}

int bitmain_axi_init()
{
    unsigned int data;
    int ret=0;

    fd = open("/dev/axi_fpga_dev", O_RDWR);
    if(fd < 0)
    {
        applog(LOG_DEBUG,"/dev/axi_fpga_dev open failed. fd = %d\n", fd);
        perror("open");
        return -1;
    }

    axi_fpga_addr = mmap(NULL, TOTAL_LEN, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(!axi_fpga_addr)
    {
        applog(LOG_DEBUG,"mmap axi_fpga_addr failed. axi_fpga_addr = 0x%x\n", axi_fpga_addr);
        return -1;
    }
    applog(LOG_DEBUG,"mmap axi_fpga_addr = 0x%x\n", axi_fpga_addr);

    //check the value in address 0xff200000
    data = *axi_fpga_addr;
    if((data & 0x0000FFFF) != HARDWARE_VERSION_VALUE)
    {
        applog(LOG_DEBUG,"data = 0x%x, and it's not equal to HARDWARE_VERSION_VALUE : 0x%x\n", data, HARDWARE_VERSION_VALUE);
        //return -1;
    }
    applog(LOG_DEBUG,"axi_fpga_addr data = 0x%x\n", data);

    fd_fpga_mem = open("/dev/fpga_mem", O_RDWR);
    if(fd_fpga_mem < 0)
    {
        applog(LOG_DEBUG,"/dev/fpga_mem open failed. fd_fpga_mem = %d\n", fd_fpga_mem);
        perror("open");
        return -1;
    }

    fpga_mem_addr = mmap(NULL, FPGA_MEM_TOTAL_LEN, PROT_READ|PROT_WRITE, MAP_SHARED, fd_fpga_mem, 0);
    if(!fpga_mem_addr)
    {
        applog(LOG_DEBUG,"mmap fpga_mem_addr failed. fpga_mem_addr = 0x%x\n", fpga_mem_addr);
        return -1;
    }
    applog(LOG_DEBUG,"mmap fpga_mem_addr = 0x%x\n", fpga_mem_addr);

    nonce2_jobid_address = fpga_mem_addr;
    job_start_address_1  = fpga_mem_addr + NONCE2_AND_JOBID_STORE_SPACE/sizeof(int);
    job_start_address_2  = fpga_mem_addr + (NONCE2_AND_JOBID_STORE_SPACE + JOB_STORE_SPACE)/sizeof(int);

    applog(LOG_DEBUG,"job_start_address_1 = 0x%x\n", job_start_address_1);
    applog(LOG_DEBUG,"job_start_address_2 = 0x%x\n", job_start_address_2);

    set_nonce2_and_job_id_store_address(PHY_MEM_NONCE2_JOBID_ADDRESS);
    set_job_start_address(PHY_MEM_JOB_START_ADDRESS_1);


    dev = calloc(sizeof(struct all_parameters), sizeof(char));
    if(!dev)
    {
        applog(LOG_DEBUG,"kmalloc for dev failed.\n");
        return -1;
    }
    else
    {
        dev->current_job_start_address = job_start_address_1;
        applog(LOG_DEBUG,"kmalloc for dev success.\n");
    }
    return ret;
}

int bitmain_axi_close()
{
    int ret = 0;

    ret = munmap((void *)axi_fpga_addr, TOTAL_LEN);
    if(ret<0)
    {
        applog(LOG_DEBUG,"munmap failed!\n");
    }

    ret = munmap((void *)fpga_mem_addr, FPGA_MEM_TOTAL_LEN);
    if(ret<0)
    {
        applog(LOG_DEBUG,"munmap failed!\n");
    }

    //free_pages((unsigned long)nonce2_jobid_address, NONCE2_AND_JOBID_STORE_SPACE_ORDER);
    //free(temp_job_start_address_1);
    //free(temp_job_start_address_2);

    close(fd);
    close(fd_fpga_mem);
}

int get_fan_control(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + FAN_CONTROL));
    applog(LOG_DEBUG,"%s: FAN_CONTROL is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_fan_control(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + FAN_CONTROL)) = value;
    applog(LOG_DEBUG,"%s: set FAN_CONTROL is 0x%x\n", __FUNCTION__, value);
    get_fan_control();
}

int get_hash_on_plug(void)
{
    int ret = -1;
    ret = *(axi_fpga_addr + HASH_ON_PLUG);

    applog(LOG_DEBUG,"%s: HASH_ON_PLUG is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_hardware_version(void)
{
    int ret = -1;
    ret = *((int *)(axi_fpga_addr + HARDWARE_VERSION));

    applog(LOG_DEBUG,"%s: HARDWARE_VERSION is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_fan_speed(unsigned char *fan_id, unsigned int *fan_speed)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + FAN_SPEED));
    *fan_speed = 0x000000ff & ret;
    *fan_id = (unsigned char)(0x00000007 & (ret >> 8));
    if(*fan_speed > 0)
    {
        applog(LOG_DEBUG,"%s: fan_id is 0x%x, fan_speed is 0x%x\n", __FUNCTION__, *fan_id, *fan_speed);
    }
    return ret;
}

int get_temperature_0_3(void)
{
    int ret = -1;
    ret = *((int *)(axi_fpga_addr + TEMPERATURE_0_3));
    //applog(LOG_DEBUG,"%s: TEMPERATURE_0_3 is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_temperature_4_7(void)
{
    int ret = -1;
    ret = *((int *)(axi_fpga_addr + TEMPERATURE_4_7));
    //applog(LOG_DEBUG,"%s: TEMPERATURE_4_7 is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_temperature_8_11(void)
{
    int ret = -1;
    ret = *((int *)(axi_fpga_addr + TEMPERATURE_8_11));
    //applog(LOG_DEBUG,"%s: TEMPERATURE_8_11 is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_temperature_12_15(void)
{
    int ret = -1;
    ret = *((int *)(axi_fpga_addr + TEMPERATURE_12_15));
    //applog(LOG_DEBUG,"%s: TEMPERATURE_12_15 is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_time_out_control(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + TIME_OUT_CONTROL));
    applog(LOG_DEBUG,"%s: TIME_OUT_CONTROL is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_time_out_control(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + TIME_OUT_CONTROL)) = value;
    applog(LOG_DEBUG,"%s: set FAN_CONTROL is 0x%x\n", __FUNCTION__, value);
    get_time_out_control();
}

int get_BC_command_buffer(unsigned int *buf)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER));
    *(buf + 0) = ret;   //this is for FIL
    ret = *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER + 1));
    *(buf + 1) = ret;
    ret = *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER + 2));
    *(buf + 2) = ret;
    applog(LOG_DEBUG,"%s: BC_COMMAND_BUFFER buf[0]: 0x%x, buf[1]: 0x%x, buf[2]: 0x%x\n", __FUNCTION__, *(buf + 0), *(buf + 1), *(buf + 2));
    return ret;
}

void set_BC_command_buffer(unsigned int *value)
{
    unsigned int buf[4] = {0};
    *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER)) = *(value + 0);      //this is for FIL
    *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER + 1)) = *(value + 1);
    *((unsigned int *)(axi_fpga_addr + BC_COMMAND_BUFFER + 2)) = *(value + 2);
    applog(LOG_DEBUG,"%s: set BC_COMMAND_BUFFER value[0]: 0x%x, value[1]: 0x%x, value[2]: 0x%x\n", __FUNCTION__, *(value + 0), *(value + 1), *(value + 2));
    get_BC_command_buffer(buf);
}

int get_nonce_number_in_fifo(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + NONCE_NUMBER_IN_FIFO));
    //applog(LOG_DEBUG,"%s: NONCE_NUMBER_IN_FIFO is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_return_nonce(unsigned int *buf)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + RETURN_NONCE));
    *(buf + 0) = ret;
    ret = *((unsigned int *)(axi_fpga_addr + RETURN_NONCE + 1));
    *(buf + 1) = ret;   //there is nonce3
    //applog(LOG_DEBUG,"%s: RETURN_NONCE buf[0] is 0x%x, buf[1] is 0x%x\n", __FUNCTION__, *(buf + 0), *(buf + 1));
    return ret;
}

int get_BC_write_command(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + BC_WRITE_COMMAND));
    applog(LOG_DEBUG,"%s: BC_WRITE_COMMAND is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_BC_write_command(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + BC_WRITE_COMMAND)) = value;
    //applog(LOG_DEBUG,"%s: set BC_WRITE_COMMAND is 0x%x\n", __FUNCTION__, value);

    if(value & BC_COMMAND_BUFFER_READY)
    {
        while(get_BC_write_command() & BC_COMMAND_BUFFER_READY)
        {
            cgsleep_ms(1);
            //applog(LOG_DEBUG,"%s ---\n", __FUNCTION__);
        }
    }
    else
    {
        get_BC_write_command();
    }
}

int get_ticket_mask(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + TICKET_MASK_FPGA));
    applog(LOG_DEBUG,"%s: TICKET_MASK_FPGA is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_ticket_mask(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + TICKET_MASK_FPGA)) = value;
    applog(LOG_DEBUG,"%s: set TICKET_MASK_FPGA is 0x%x\n", __FUNCTION__, value);
    get_ticket_mask();
}

int get_job_id(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + JOB_ID));
    applog(LOG_DEBUG,"%s: JOB_ID is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_job_id(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + JOB_ID)) = value;
    applog(LOG_DEBUG,"%s: set JOB_ID is 0x%x\n", __FUNCTION__, value);
    get_job_id();
}

int get_job_length(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + JOB_LENGTH));
    applog(LOG_DEBUG,"%s: JOB_LENGTH is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_job_length(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + JOB_LENGTH)) = value;
    applog(LOG_DEBUG,"%s: set JOB_LENGTH is 0x%x\n", __FUNCTION__, value);
    get_job_id();
}


int get_block_header_version(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + BLOCK_HEADER_VERSION));
    applog(LOG_DEBUG,"%s: BLOCK_HEADER_VERSION is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_block_header_version(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + BLOCK_HEADER_VERSION)) = value;
    applog(LOG_DEBUG,"%s: set BLOCK_HEADER_VERSION is 0x%x\n", __FUNCTION__, value);
    get_block_header_version();
}

int get_time_stamp()
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + TIME_STAMP));
    applog(LOG_DEBUG,"%s: TIME_STAMP is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_time_stamp(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + TIME_STAMP)) = value;
    applog(LOG_DEBUG,"%s: set TIME_STAMP is 0x%x\n", __FUNCTION__, value);
    get_time_stamp();
}

int get_target_bits(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + TARGET_BITS));
    applog(LOG_DEBUG,"%s: TARGET_BITS is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_target_bits(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + TARGET_BITS)) = value;
    applog(LOG_DEBUG,"%s: set TARGET_BITS is 0x%x\n", __FUNCTION__, value);
    get_target_bits();
}

int get_pre_header_hash(unsigned int *buf)
{
    int ret = -1;
    *(buf + 0) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH));
    *(buf + 1) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 1));
    *(buf + 2) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 2));
    *(buf + 3) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 3));
    *(buf + 4) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 4));
    *(buf + 5) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 5));
    *(buf + 6) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 6));
    *(buf + 7) = *((unsigned int *)(axi_fpga_addr + PRE_HEADER_HASH + 7));
    applog(LOG_DEBUG,"%s: PRE_HEADER_HASH buf[0]: 0x%x, buf[1]: 0x%x, buf[2]: 0x%x, buf[3]: 0x%x, buf[4]: 0x%x, buf[5]: 0x%x, buf[6]: 0x%x, buf[7]: 0x%x\n", __FUNCTION__, *(buf + 0), *(buf + 1), *(buf + 2), *(buf + 3), *(buf + 4), *(buf + 5), *(buf + 6), *(buf + 7));
    ret = *(buf + 7);
    return ret;
}

void set_pre_header_hash(unsigned int *value)
{
    unsigned int buf[8] = {0};
    *(axi_fpga_addr + PRE_HEADER_HASH) = *(value + 0);
    *(axi_fpga_addr + PRE_HEADER_HASH + 1) = *(value + 1);
    *(axi_fpga_addr + PRE_HEADER_HASH + 2) = *(value + 2);
    *(axi_fpga_addr + PRE_HEADER_HASH + 3) = *(value + 3);
    *(axi_fpga_addr + PRE_HEADER_HASH + 4) = *(value + 4);
    *(axi_fpga_addr + PRE_HEADER_HASH + 5) = *(value + 5);
    *(axi_fpga_addr + PRE_HEADER_HASH + 6) = *(value + 6);
    *(axi_fpga_addr + PRE_HEADER_HASH + 7) = *(value + 7);
    applog(LOG_DEBUG,"%s: set PRE_HEADER_HASH value[0]: 0x%x, value[1]: 0x%x, value[2]: 0x%x, value[3]: 0x%x, value[4]: 0x%x, value[5]: 0x%x, value[6]: 0x%x, value[7]: 0x%x\n", __FUNCTION__, *(value + 0), *(value + 1), *(value + 2), *(value + 3), *(value + 4), *(value + 5), *(value + 6), *(value + 7));
    //get_pre_header_hash(buf);
}

int get_coinbase_length_and_nonce2_length(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + COINBASE_AND_NONCE2_LENGTH));
    applog(LOG_DEBUG,"%s: COINBASE_AND_NONCE2_LENGTH is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_coinbase_length_and_nonce2_length(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + COINBASE_AND_NONCE2_LENGTH)) = value;
    applog(LOG_DEBUG,"%s: set COINBASE_AND_NONCE2_LENGTH is 0x%x\n", __FUNCTION__, value);
    get_coinbase_length_and_nonce2_length();
}

int get_work_nonce2(unsigned int *buf)
{
    int ret = -1;
    *(buf + 0) = *((unsigned int *)(axi_fpga_addr + WORK_NONCE_2));
    *(buf + 1) = *((unsigned int *)(axi_fpga_addr + WORK_NONCE_2 + 1));
    applog(LOG_DEBUG,"%s: WORK_NONCE_2 buf[0]: 0x%x, buf[1]: 0x%x\n", __FUNCTION__, *(buf + 0), *(buf + 1));
    return ret;
}

void set_work_nonce2(unsigned int *value)
{
    unsigned int buf[2] = {0};
    *((unsigned int *)(axi_fpga_addr + WORK_NONCE_2)) = *(value + 0);
    *((unsigned int *)(axi_fpga_addr + WORK_NONCE_2 + 1)) = *(value + 1);
    applog(LOG_DEBUG,"%s: set WORK_NONCE_2 value[0]: 0x%x, value[1]: 0x%x\n", __FUNCTION__, *(value + 0), *(value + 1));
    get_work_nonce2(buf);
}

int get_merkle_bin_number(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + MERKLE_BIN_NUMBER));
    ret = ret & 0x0000ffff;
    applog(LOG_DEBUG,"%s: MERKLE_BIN_NUMBER is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_merkle_bin_number(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + MERKLE_BIN_NUMBER)) = value & 0x0000ffff;
    applog(LOG_DEBUG,"%s: set MERKLE_BIN_NUMBER is 0x%x\n", __FUNCTION__, value & 0x0000ffff);
    get_merkle_bin_number();
}

int get_nonce_fifo_interrupt(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + NONCE_FIFO_INTERRUPT));
    applog(LOG_DEBUG,"%s: NONCE_FIFO_INTERRUPT is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_nonce_fifo_interrupt(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + NONCE_FIFO_INTERRUPT)) = value;
    applog(LOG_DEBUG,"%s: set NONCE_FIFO_INTERRUPT is 0x%x\n", __FUNCTION__, value);
    get_nonce_fifo_interrupt();
}

int get_dhash_acc_control(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + DHASH_ACC_CONTROL));
    applog(LOG_DEBUG,"%s: DHASH_ACC_CONTROL is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_dhash_acc_control(unsigned int value)
{
    int a = 10;
    *((unsigned int *)(axi_fpga_addr + DHASH_ACC_CONTROL)) = value;
    applog(LOG_DEBUG,"%s: set DHASH_ACC_CONTROL is 0x%x\n", __FUNCTION__, value);
    while (a>0)
    {
        if ((value | NEW_BLOCK) == (get_dhash_acc_control() |NEW_BLOCK))
            break;
        *((unsigned int *)(axi_fpga_addr + DHASH_ACC_CONTROL)) = value;
        a--;
        cgsleep_ms(2);
    }
    if (a == 0)
        applog(LOG_DEBUG,"%s set DHASH_ACC_CONTROL failed!",__FUNCTION__);
}

void set_TW_write_command(unsigned int *value)
{
    unsigned int i;
    for(i=0; i<TW_WRITE_COMMAND_LEN/sizeof(unsigned int); i++)
    {
        *((unsigned int *)(axi_fpga_addr + TW_WRITE_COMMAND + i)) = *(value + i);       //this is for FIL
        //applog(LOG_DEBUG,"%s: set TW_WRITE_COMMAND value[%d]: 0x%x\n", __FUNCTION__, i, *(value + i));
    }
    //applog(LOG_DEBUG,"%s: set TW_WRITE_COMMAND value[0]: 0x%x, value[1]: 0x%x, value[2]: 0x%x, value[3]: 0x%x\n", __FUNCTION__, *(value + 0), *(value + 1), *(value + 2), *(value + 3));
}

void set_TW_write_command_vil(unsigned int *value)
{
    unsigned int i;
    for(i=0; i<TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int); i++)
    {
        *((unsigned int *)(axi_fpga_addr + TW_WRITE_COMMAND + i)) = *(value + i);//this is for FIL
        //applog(LOG_DEBUG,"%s: set TW_WRITE_COMMAND value[%d]: 0x%x\n", __FUNCTION__, i, *(value + i));
    }
    //applog(LOG_DEBUG,"%s: set TW_WRITE_COMMAND value[0]: 0x%x, value[1]: 0x%x, value[2]: 0x%x, value[3]: 0x%x\n", __FUNCTION__, *(value + 0), *(value + 1), *(value + 2), *(value + 3));
}

int get_buffer_space(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + BUFFER_SPACE));
    //applog(LOG_DEBUG,"%s: work fifo ready is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

int get_hash_counting_number(void)
{
    int ret = -1;
    ret = *((unsigned int *)(axi_fpga_addr + HASH_COUNTING_NUMBER_FPGA));
    applog(LOG_DEBUG,"%s: DHASH_ACC_CONTROL is 0x%x\n", __FUNCTION__, ret);
    return ret;
}

void set_hash_counting_number(unsigned int value)
{
    *((unsigned int *)(axi_fpga_addr + HASH_COUNTING_NUMBER_FPGA)) = value;
    applog(LOG_DEBUG,"%s: set DHASH_ACC_CONTROL is 0x%x\n", __FUNCTION__, value);
    get_hash_counting_number();
}


//application related
void check_chain()
{
    int ret = 0, i;

    dev->chain_num = 0;

    ret = get_hash_on_plug();

    if(ret < 0)
    {
        applog(LOG_DEBUG,"%s: get_hash_on_plug functions error\n");
    }
    else
    {
        for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if((ret >> i) & 0x1)
            {
                dev->chain_exist[i] = 1;
                dev->chain_num++;
            }
            else
            {
                dev->chain_exist[i] = 0;
            }
        }
    }
}

void check_fan()
{
    unsigned char i=0, j=0;
    unsigned char fan_id = 0;
    unsigned int fan_speed;

    for(j=0; j < 2; j++)    //means check for twice to make sure find out all fan
    {
        for(i=0; i < BITMAIN_MAX_FAN_NUM; i++)
        {
            if(get_fan_speed(&fan_id, &fan_speed) != -1)
            {
                dev->fan_speed_value[fan_id] = fan_speed * 60 * 2;
                if((fan_speed > 0) && (dev->fan_exist[fan_id] == 0))
                {
                    dev->fan_exist[fan_id] = 1;
                    dev->fan_num++;
                    dev->fan_exist_map |= (0x1 << fan_id);
                }
                else if((fan_speed == 0) && (dev->fan_exist[fan_id] == 1))
                {
                    dev->fan_exist[fan_id] = 0;
                    dev->fan_num--;
                    dev->fan_exist_map &= !(0x1 << fan_id);
                }
                if(dev->fan_speed_top1 < dev->fan_speed_value[fan_id])
                    dev->fan_speed_top1 = dev->fan_speed_value[fan_id];
            }
        }
    }
}

int get_all_temperature()
{
    int ret = 0;
    int ret_value = 0;
    unsigned int i = 0;
    int temperature = 0, highest_temp = 0;
    int temperature_gap[BITMAIN_MAX_CHAIN_NUM] = {0};
    int biggest_gap = 0;


    dev->temp_top1_last = dev->temp_top1;
    dev->temp_num = 0;
    dev->temp_top1 = 0;
    dev->temp_sensor_map = 0;

    ret = get_temperature_0_3();
    if(ret != -1)
    {
        for(i=0; i < 4; i++)
        {
            temperature = (ret >> i*8) & 0xff;
            if((dev->chain_exist[i] == 1) && temperature)
            {
                dev->temp_sensor_map |= (0x1 << i);
                dev->temp_num++;
                dev->temp[i] = temperature;
            }
            else if((dev->chain_exist[i] == 0) && temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is not exist, but it has temperature:%d\n", __FUNCTION__, i, temperature);
            }
            else if((dev->chain_exist[i] == 1) && !temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is exist, but its temperature is:%d\n", __FUNCTION__, i, temperature);
            }
            else
            {
                //applog(LOG_DEBUG,"%s: no chain%d no temperature\n", __FUNCTION__, i);
            }
        }
    }

    ret = get_temperature_4_7();
    if(ret != -1)
    {
        for(i=0; i<4; i++)
        {
            temperature = (ret >> i*8) & 0xff;
            if((dev->chain_exist[i+4] == 1) && temperature)
            {
                dev->temp_sensor_map |= (0x1 << (i+4));
                dev->temp_num++;
                dev->temp[i+4] = temperature;
            }
            else if((dev->chain_exist[i+4] == 0) && temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is not exist, but it has temperature:%d\n", __FUNCTION__, i+4, temperature);
            }
            else if((dev->chain_exist[i+4] == 1) && !temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is exist, but its temperature is:%d\n", __FUNCTION__, i+4, temperature);
            }
            else
            {
                //applog(LOG_DEBUG,"%s: no chain%d no temperature\n", __FUNCTION__, i+4);
            }
        }
    }

    ret = get_temperature_8_11();
    if(ret != -1)
    {
        for(i=0; i<4; i++)
        {
            temperature = (ret >> i*8) & 0xff;
            if((dev->chain_exist[i+8] == 1) && temperature)
            {
                dev->temp_sensor_map |= (0x1 << (i+8));
                dev->temp_num++;
                dev->temp[i+8] = temperature;
            }
            else if((dev->chain_exist[i+8] == 0) && temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is not exist, but it has temperature:%d\n", __FUNCTION__, i+8, temperature);
            }
            else if((dev->chain_exist[i+8] == 1) && !temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is exist, but its temperature is:%d\n", __FUNCTION__, i+8, temperature);
            }
            else
            {
                //applog(LOG_DEBUG,"%s: no chain%d no temperature\n", __FUNCTION__, i+8);
            }
        }
    }

    ret = get_temperature_12_15();
    if(ret != -1)
    {
        for(i=0; i<4; i++)
        {
            temperature = (ret >> i*8) & 0xff;
            if((dev->chain_exist[i+12] == 1) && temperature)
            {
                dev->temp_sensor_map |= (0x1 << (i+12));
                dev->temp_num++;
                dev->temp[i+12] = temperature;
            }
            else if((dev->chain_exist[i+12] == 0) && temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is not exist, but it has temperature:%d\n", __FUNCTION__, i+12, temperature);
            }
            else if((dev->chain_exist[i+12] == 1) && !temperature)
            {
                ret_value = -1;
                applog(LOG_DEBUG,"%s: chain%d is exist, but its temperature is:%d\n", __FUNCTION__, i+12, temperature);
            }
            else
            {
                //applog(LOG_DEBUG,"%s: no chain%d no temperature\n", __FUNCTION__, i+12);
            }
        }
    }

    for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->temp[i] > highest_temp)
        {
            highest_temp = dev->temp[i];
            dev->temp_top1 = dev->temp[i];
        }
    }

    if((dev->temp_top1 - dev->temp_top1_last < 2) && (dev->temp_top1 - dev->temp_top1_last > -2))
    {
        dev->temp_top1_last = dev->temp_top1;
    }
    return ret_value;
}

void set_PWM(unsigned char pwm_percent)
{
    uint16_t pwm_high_value = 0, pwm_low_value = 0;
    int temp_pwm_percent = 0;

    temp_pwm_percent = pwm_percent;

    if(temp_pwm_percent < MIN_PWM_PERCENT)
    {
        temp_pwm_percent = MIN_PWM_PERCENT;
    }

    if(temp_pwm_percent > MAX_PWM_PERCENT)
    {
        temp_pwm_percent = MAX_PWM_PERCENT;
    }

    pwm_high_value = temp_pwm_percent * PWM_SCALE / 100;
    pwm_low_value  = (100 - temp_pwm_percent) * PWM_SCALE / 100;
    dev->pwm_value = (pwm_high_value << 16) | pwm_low_value;
    dev->pwm_percent = temp_pwm_percent;

    set_fan_control(dev->pwm_value);
}

void set_PWM_according_to_temperature()
{
    int  pwm_percent = 0, temp_change = 0;
    temp_highest = dev->temp_top1;
    if(temp_highest >= MAX_FAN_TEMP)
    {
        applog(LOG_DEBUG,"%s: Temperature is higher than %d 'C\n", __FUNCTION__, temp_highest);
    }

    if(dev->fan_eft)
    {
        if((dev->fan_pwm >= 0) && (dev->fan_pwm <= 100))
        {
            set_PWM(dev->fan_pwm);
            return;
        }
    }

    temp_change = temp_highest - last_temperature;

    if(temp_highest >= MAX_FAN_TEMP || temp_highest == 0)
    {
        set_PWM(MAX_PWM_PERCENT);
        dev->fan_pwm = MAX_PWM_PERCENT;
        applog(LOG_DEBUG,"%s: Set PWM percent : MAX_PWM_PERCENT\n", __FUNCTION__);
        return;
    }

    if(temp_highest <= MIN_FAN_TEMP)
    {
        set_PWM(MIN_PWM_PERCENT);
        dev->fan_pwm = MIN_PWM_PERCENT;
        applog(LOG_DEBUG,"%s: Set PWM percent : MIN_PWM_PERCENT\n", __FUNCTION__);
        return;
    }

    if(temp_change >= TEMP_INTERVAL || temp_change <= -TEMP_INTERVAL)
    {
        pwm_percent = MIN_PWM_PERCENT + (temp_highest -MIN_FAN_TEMP) * PWM_ADJUST_FACTOR;
        if(pwm_percent < 0)
        {
            pwm_percent = 0;
        }
        dev->fan_pwm = pwm_percent;
        applog(LOG_DEBUG,"%s: Set PWM percent : %d\n", __FUNCTION__, pwm_percent);
        set_PWM(pwm_percent);
        last_temperature = temp_highest;
    }
}

static void get_plldata(int type,int freq,uint32_t * reg_data,uint16_t * reg_data2, uint32_t *vil_data)
{
    uint32_t i;
    char freq_str[10];
    sprintf(freq_str,"%d", freq);
    char plldivider1[32] = {0};
    char plldivider2[32] = {0};
    char vildivider[32] = {0};

    if(type == 1385)
    {
        for(i=0; i < sizeof(freq_pll_1385)/sizeof(freq_pll_1385[0]); i++)
        {
            if( memcmp(freq_pll_1385[i].freq, freq_str, sizeof(freq_pll_1385[i].freq)) == 0)
                break;
        }
    }

    if(i == sizeof(freq_pll_1385)/sizeof(freq_pll_1385[0]))
    {
        i = 4;
    }

    sprintf(plldivider1, "%08x", freq_pll_1385[i].fildiv1);
    sprintf(plldivider2, "%04x", freq_pll_1385[i].fildiv2);
    sprintf(vildivider, "%04x", freq_pll_1385[i].vilpll);

    *reg_data = freq_pll_1385[i].fildiv1;
    *reg_data2 = freq_pll_1385[i].fildiv2;
    *vil_data = freq_pll_1385[i].vilpll;
}

void set_frequency(unsigned short int frequency)
{
    unsigned char buf[9] = {0,0,0,0,0,0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned char i;
    unsigned int ret, value;
    uint32_t reg_data_pll = 0;
    uint16_t reg_data_pll2 = 0;
    uint32_t reg_data_vil = 0;

    applog(LOG_DEBUG,"\n--- %s\n", __FUNCTION__);

    get_plldata(1385, frequency, &reg_data_pll, &reg_data_pll2, &reg_data_vil);
    applog(LOG_DEBUG,"%s: frequency = %d\n", __FUNCTION__, frequency);

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            //applog(LOG_DEBUG,"%s: i = %d\n", __FUNCTION__, i);
            if(!opt_multi_version)  // fil mode
            {
                memset(buf,0,sizeof(buf));
                memset(cmd_buf,0,sizeof(cmd_buf));
                buf[0] = 0;
                buf[0] |= SET_PLL_DIVIDER1;
                buf[1] = (reg_data_pll >> 16) & 0xff;
                buf[2] = (reg_data_pll >> 8) & 0xff;
                buf[3] = (reg_data_pll >> 0) & 0xff;
                buf[3] |= CRC5(buf, 4*8 - 5);
                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];

                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);

                cgsleep_us(3000);

                memset(buf,0,sizeof(buf));
                memset(cmd_buf,0,sizeof(cmd_buf));
                buf[0] = SET_PLL_DIVIDER2;
                buf[0] |= COMMAND_FOR_ALL;
                buf[1] = 0;     //addr
                buf[2] = reg_data_pll2 >> 8;
                buf[3] = reg_data_pll2& 0x0ff;
                buf[3] |= CRC5(buf, 4*8 - 5);
                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];

                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);

                dev->freq[i] = frequency;

                cgsleep_us(5000);
            }
            else    // vil
            {
                memset(buf,0,9);
                memset(cmd_buf,0,3*sizeof(int));
                buf[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
                buf[1] = 0x09;
                buf[2] = 0;
                buf[3] = PLL_PARAMETER;
                buf[4] = (reg_data_vil >> 24) & 0xff;
                buf[5] = (reg_data_vil >> 16) & 0xff;
                buf[6] = (reg_data_vil >> 8) & 0xff;
                buf[7] = (reg_data_vil >> 0) & 0xff;
                buf[8] = CRC5(buf, 8*8);

                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
                cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];;
                cmd_buf[2] = buf[8]<<24;

                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);

                dev->freq[i] = frequency;
                cgsleep_us(10000);
            }
        }
    }
}

void set_frequency_with_addr(unsigned short int frequency,unsigned char mode,unsigned char addr, unsigned char chain)
{
    unsigned char buf[9] = {0,0,0,0,0,0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned char i;
    unsigned int ret, value;
    uint32_t reg_data_pll = 0;
    uint16_t reg_data_pll2 = 0;
    uint32_t reg_data_vil = 0;
    i = chain;

    applog(LOG_DEBUG,"\n--- %s\n", __FUNCTION__);

    get_plldata(1385, frequency, &reg_data_pll, &reg_data_pll2, &reg_data_vil);
    applog(LOG_DEBUG,"%s: frequency = %d\n", __FUNCTION__, frequency);

    //applog(LOG_DEBUG,"%s: i = %d\n", __FUNCTION__, i);
    if(!opt_multi_version)  // fil mode
    {
        memset(buf,0,sizeof(buf));
        memset(cmd_buf,0,sizeof(cmd_buf));
        buf[0] = 0;
        buf[0] |= SET_PLL_DIVIDER1;
        buf[1] = (reg_data_pll >> 16) & 0xff;
        buf[2] = (reg_data_pll >> 8) & 0xff;
        buf[3] = (reg_data_pll >> 0) & 0xff;
        buf[3] |= CRC5(buf, 4*8 - 5);
        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];

        set_BC_command_buffer(cmd_buf);
        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);

        cgsleep_us(3000);

        memset(buf,0,sizeof(buf));
        memset(cmd_buf,0,sizeof(cmd_buf));
        buf[0] = SET_PLL_DIVIDER2;
        buf[0] |= COMMAND_FOR_ALL;
        buf[1] = 0;     //addr
        buf[2] = reg_data_pll2 >> 8;
        buf[3] = reg_data_pll2& 0x0ff;
        buf[3] |= CRC5(buf, 4*8 - 5);
        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];

        set_BC_command_buffer(cmd_buf);
        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);

        dev->freq[i] = frequency;

        cgsleep_us(5000);
    }
    else    // vil
    {
        memset(buf,0,9);
        memset(cmd_buf,0,3*sizeof(int));
        if(mode)
            buf[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
        else
            buf[0] = VIL_COMMAND_TYPE | SET_CONFIG;
        buf[1] = 0x09;
        buf[2] = addr;
        buf[3] = PLL_PARAMETER;
        buf[4] = (reg_data_vil >> 24) & 0xff;
        buf[5] = (reg_data_vil >> 16) & 0xff;
        buf[6] = (reg_data_vil >> 8) & 0xff;
        buf[7] = (reg_data_vil >> 0) & 0xff;
        buf[8] = CRC5(buf, 8*8);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];;
        cmd_buf[2] = buf[8]<<24;

        set_BC_command_buffer(cmd_buf);
        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);

        dev->freq[i] = frequency;
        cgsleep_us(10000);
    }
}


void clear_nonce_fifo()
{
    unsigned char i;
    unsigned int buf[2] = {0};

    for(i=0; i<3; i++)  //loop 3 times for making sure read out all nonce/register data
    {
        while(get_nonce_number_in_fifo() & MAX_NONCE_NUMBER_IN_FIFO)
        {
            get_return_nonce(buf);
        }
    }
}

void clear_register_value_buf()
{
    pthread_mutex_lock(&reg_mutex);
    reg_value_buf.p_wr = 0;
    reg_value_buf.p_rd = 0;
    reg_value_buf.reg_value_num = 0;
    //memset(reg_value_buf.reg_buffer, 0, sizeof(struct reg_content)*MAX_NONCE_NUMBER_IN_FIFO);
    pthread_mutex_unlock(&reg_mutex);
}

void read_asic_register(unsigned char chain, unsigned char mode, unsigned char chip_addr, unsigned char reg_addr)
{
    unsigned char buf[5] = {0,0,0,0,0};
    unsigned char buf_vil[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value;

    if(!opt_multi_version)    // fil mode but on cgminer.c it is set always to 1 / true!!!
    {
        buf[0] = GET_STATUS;
        buf[1] = chip_addr;
        buf[2] = reg_addr;
        if (mode)   //all
            buf[0] |= COMMAND_FOR_ALL;
        buf[3] = CRC5(buf, 4*8 - 5);
        applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        set_BC_command_buffer(cmd_buf);

        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
    else    // vil mode
    {
        buf[0] = VIL_COMMAND_TYPE | GET_STATUS;
        if(mode)
            buf[0] |= VIL_ALL;
        buf[1] = 0x05;
        buf[2] = chip_addr;
        buf[3] = reg_addr;
        buf[4] = CRC5(buf, 4*8);
        applog(LOG_DEBUG,"%s:VIL buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x, buf[4]=0x%x", __FUNCTION__, buf[0], buf[1], buf[2], buf[3], buf[4]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24;

        while (1)
        {
            if (((ret = get_BC_write_command()) & 0x80000000) == 0)
                break;
            cgsleep_ms(1);
        }
        set_BC_command_buffer(cmd_buf);

        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
}

void read_temp(unsigned char device,unsigned reg,unsigned char data,unsigned char write,unsigned char chip_addr,int chain)
{
    unsigned char buf[9] = {0,0,0,0,0,0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value,i;
    i = chain;
    if(!opt_multi_version)
    {
        printf("fil mode do not support temp reading");
    }
    else
    {
        buf[0] = VIL_COMMAND_TYPE  | SET_CONFIG;
        buf[1] = 0x09;
        buf[2] = chip_addr;
        buf[3] = GENERAL_I2C_COMMAND;
        buf[4] = 0x01;
        buf[5] = device | write;
        buf[6] = reg;
        buf[7] = data;
        buf[8] = CRC5(buf, 8*8);
        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
        cmd_buf[2] = buf[8]<<24;
        while (1)
        {
            ret = get_BC_write_command();
            if ((ret & 0x80000000) == 0)
                break;
            cgsleep_ms(1);
        }
        set_BC_command_buffer(cmd_buf);
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }

}

static void suffix_string_c5(uint64_t val, char *buf, size_t bufsiz, int sigdigits,bool display)
{
    const double  dkilo = 1000.0;
    const uint64_t kilo = 1000ull;
    const uint64_t mega = 1000000ull;
    const uint64_t giga = 1000000000ull;
    const uint64_t tera = 1000000000000ull;
    const uint64_t peta = 1000000000000000ull;
    const uint64_t exa  = 1000000000000000000ull;
    char suffix[2] = "";
    bool decimal = true;
    double dval;
    /*
        if (val >= exa)
        {
            val /= peta;
            dval = (double)val / dkilo;
            strcpy(suffix, "E");
        }
        else if (val >= peta)
        {
            val /= tera;
            dval = (double)val / dkilo;
            strcpy(suffix, "P");
        }
        else if (val >= tera)
        {
            val /= giga;
            dval = (double)val / dkilo;
            strcpy(suffix, "T");
        }
        else */if (val >= giga)
    {
        val /= mega;
        dval = (double)val / dkilo;
        strcpy(suffix, "G");
    }
    else if (val >= mega)
    {
        val /= kilo;
        dval = (double)val / dkilo;
        strcpy(suffix, "M");
    }
    else if (val >= kilo)
    {
        dval = (double)val / dkilo;
        strcpy(suffix, "K");
    }
    else
    {
        dval = val;
        decimal = false;
    }

    if (!sigdigits)
    {
        if (decimal)
            snprintf(buf, bufsiz, "%.3g%s", dval, suffix);
        else
            snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
    }
    else
    {
        /* Always show sigdigits + 1, padded on right with zeroes
         * followed by suffix */
        int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);
        if(display)
            snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
        else
            snprintf(buf, bufsiz, "%*.*f", sigdigits + 1, ndigits, dval);

    }
}


void check_asic_reg(unsigned int reg)
{

    unsigned char i, j, not_reg_data_time=0;
    int nonce_number = 0;
    unsigned int buf[2] = {0};
    unsigned int reg_value_num=0;
    unsigned int temp_nonce = 0;
    unsigned char reg_buf[5] = {0,0,0,0,0};
    int read_num = 0;
    uint64_t tmp_rate = 0;
    rerun_all:
    clear_register_value_buf();
    tmp_rate = 0;
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        read_num = 0;
        if(dev->chain_exist[i] == 1)
        {
            tmp_rate = 0;
            applog(LOG_DEBUG,"%s: check chain J%d \n", __FUNCTION__, i+1);
            read_asic_register(i, 1, 0, reg);
            if (reg ==CHIP_ADDRESS)
                dev->chain_asic_num[i] = 0;

            while(not_reg_data_time < 3)    //if there is no register value for 3 times, we can think all asic return their address
            {
                cgsleep_ms(300);

                pthread_mutex_lock(&reg_mutex);

                reg_value_num = reg_value_buf.reg_value_num;
                //applog(LOG_DEBUG,"%s: reg_value_num = %d\n", __FUNCTION__, reg_value_num);
                pthread_mutex_unlock(&reg_mutex);
                if((reg_value_num >= MAX_NONCE_NUMBER_IN_FIFO || reg_value_buf.p_rd >= MAX_NONCE_NUMBER_IN_FIFO) && not_reg_data_time <3)
                {
                    not_reg_data_time ++;
                    goto rerun_all;
                }
                if(not_reg_data_time == 3)
                {
                    return;
                }

                //applog(LOG_DEBUG,"%s: reg_value_buf.reg_value_num = 0x%x\n", __FUNCTION__, reg_value_num);

                if(reg_value_num > 0)
                {
                    not_reg_data_time = 0;

                    applog(LOG_DEBUG,"%s: reg_value_buf.reg_value_num = %d\n", __FUNCTION__, reg_value_num);

                    for(j = 0; j < reg_value_num; j++)
                    {
                        pthread_mutex_lock(&reg_mutex);

                        //applog(LOG_DEBUG,"%\n");
                        if(reg_value_buf.reg_buffer[reg_value_buf.p_rd].chain_number != i)
                        {
                            applog(LOG_DEBUG,"%s: the return data is from chain%d, but it should be from chain%d\n", __FUNCTION__, reg_value_buf.reg_buffer[reg_value_buf.p_rd].chain_number, i);
                            pthread_mutex_unlock(&reg_mutex);
                            continue;
                        }
                        //applog(LOG_DEBUG,"@\n");

                        reg_buf[3] = (unsigned char)(reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value & 0xff);
                        reg_buf[2] = (unsigned char)((reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value >> 8) & 0xff);
                        reg_buf[1] = (unsigned char)((reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value >> 16)& 0xff);
                        reg_buf[0] = (unsigned char)((reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value >> 24)& 0xff);

                        applog(LOG_DEBUG,"%s: reg_value = 0x%x\n", __FUNCTION__, reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value);

                        reg_value_buf.p_rd++;
                        reg_value_buf.reg_value_num--;
                        if(reg_value_buf.p_rd >= MAX_NONCE_NUMBER_IN_FIFO)
                        {
                            reg_value_buf.p_rd = 0;
                        }
                        //applog(LOG_DEBUG,"%s: reg_value_buf.reg_value_num = %d\n", __FUNCTION__, reg_value_buf.reg_value_num);
                        pthread_mutex_unlock(&reg_mutex);

                        if(reg == CHIP_ADDRESS)
                        {
                            dev->chain_asic_num[i]++;
                        }

                        if(reg == PLL_PARAMETER)
                        {
                            applog(LOG_DEBUG,"%s: the asic freq is 0x%x\n", __FUNCTION__, reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value);
                        }

                        if(reg == 0x08)
                        {
                            int i;
                            uint64_t temp_hash_rate = 0;
                            uint8_t rate_buf[10];
                            uint8_t displayed_rate[16];
                            for(i = 0; i < 4; i++)
                            {
                                sprintf(rate_buf + 2*i,"%02x",reg_buf[i]);
                            }
                            applog(LOG_DEBUG,"%s: hashrate is %s\n", __FUNCTION__, rate_buf);
                            temp_hash_rate = strtol(rate_buf,NULL,16);
                            temp_hash_rate = (temp_hash_rate << 24);
                            tmp_rate += temp_hash_rate;
                            read_num ++;
                        }
                    }
                    if(reg == CHIP_ADDRESS)
                    {
                        if (dev->chain_asic_num[i] == CHAIN_ASIC_NUM)
                            break;
                    }
                }
                else
                {
                    cgsleep_ms(100);
                    not_reg_data_time++;
                    applog(LOG_DEBUG,"%s: no asic address register come back for %d time.\n", __FUNCTION__, not_reg_data_time);
                }
            }

            not_reg_data_time = 0;

            if(reg == CHIP_ADDRESS)
            {
                if(dev->chain_asic_num[i] > dev->max_asic_num_in_one_chain)
                {
                    dev->max_asic_num_in_one_chain = dev->chain_asic_num[i];
                }
                applog(LOG_DEBUG,"%s: chain J%d has %d ASIC\n", __FUNCTION__, i+1, dev->chain_asic_num[i]);
            }
            if(read_num == CHAIN_ASIC_NUM)
            {
                rate[i] = tmp_rate;
                suffix_string_c5(rate[i], (char * )displayed_rate[i], sizeof(displayed_rate[i]), 6,false);
                rate_error[i] = 0;
                applog(LOG_DEBUG,"%s: chain %d hashrate is %s\n", __FUNCTION__, i, displayed_rate[i]);
            }
            if(read_num == 0 || status_error )
            {
                rate_error[i]++;
                if(rate_error[i] > 3 || status_error)
                {
                    rate[i] = 0;
                    suffix_string_c5(rate[i], (char * )displayed_rate[i], sizeof(displayed_rate[i]), 6,false);
                }
            }
            //set_nonce_fifo_interrupt(get_nonce_fifo_interrupt() & ~(FLUSH_NONCE3_FIFO));
            clear_register_value_buf();
        }
    }
}

#define RETRY_NUM 5
unsigned int check_asic_reg_with_addr(unsigned int reg,unsigned int chip_addr,unsigned int chain, int check_num)
{
    unsigned char i, j, not_reg_data_time=0;
    int nonce_number = 0;
    unsigned int reg_value_num=0;
    unsigned int reg_buf = 0;
    i = chain;
    rerun:
    clear_register_value_buf();
    read_asic_register(i, 0, chip_addr, reg);
    cgsleep_ms(80);

    while(not_reg_data_time < RETRY_NUM)    //if there is no register value for 3 times, we can think all asic return their address
    {
        pthread_mutex_lock(&reg_mutex);
        reg_value_num = reg_value_buf.reg_value_num;
        //applog(LOG_NOTICE,"%s: p_wr = %d reg_value_num = %d\n", __FUNCTION__,reg_value_buf.p_wr,reg_value_buf.reg_value_num);
        pthread_mutex_unlock(&reg_mutex);
        applog(LOG_DEBUG,"%s: reg_value_num %d", __FUNCTION__, reg_value_num);
        if((reg_value_num >= MAX_NONCE_NUMBER_IN_FIFO || reg_value_buf.p_rd >= MAX_NONCE_NUMBER_IN_FIFO ||reg_value_num ==0 ) && not_reg_data_time <RETRY_NUM)
        {
            not_reg_data_time ++;
            goto rerun;
        }
        if(not_reg_data_time >= RETRY_NUM)
        {
            return 0;
        }

        pthread_mutex_lock(&reg_mutex);
        for(i = 0; i < reg_value_num; i++)
        {
            reg_buf = reg_value_buf.reg_buffer[reg_value_buf.p_rd].reg_value;
            applog(LOG_DEBUG,"%s: chip %x reg %x reg_buff %x", __FUNCTION__, chip_addr,reg,reg_buf);
            reg_value_buf.p_rd++;
            reg_value_buf.reg_value_num--;
            if(reg_value_buf.p_rd < MAX_NONCE_NUMBER_IN_FIFO)
            {
                reg_value_buf.p_rd = 0;
            }
            if(reg == GENERAL_I2C_COMMAND)
            {
                if((reg_buf & 0xc0000000) == 0x0)
                {
                    pthread_mutex_unlock(&reg_mutex);
                    clear_register_value_buf();
                    return reg_buf;
                }
                else
                {
                    pthread_mutex_unlock(&reg_mutex);
                    clear_register_value_buf();
                    return 0;
                }
            }
        }
        pthread_mutex_unlock(&reg_mutex);
    }
    //set_nonce_fifo_interrupt(get_nonce_fifo_interrupt() & ~(FLUSH_NONCE3_FIFO));
    clear_register_value_buf();
    return 0;
}


unsigned int wait_iic_ok(unsigned int chip_addr,unsigned int chain,bool update)
{
    int fail_time = 0;
    unsigned int ret = 0;
    while(fail_time < 2)
    {
        ret = check_asic_reg_with_addr(GENERAL_I2C_COMMAND,chip_addr,chain,1);
        if (ret != 0)
        {
            return ret;
        }
        else
        {
            fail_time++;
            cgsleep_ms(1);
        }
    }
    return 0;
}

unsigned int check_reg_temp(unsigned char device,unsigned reg,unsigned char data,unsigned char write,unsigned char chip_addr,int chain)
{
    int fail_time =0;
    unsigned int ret;
    if(!write)
    {
        do
        {
            wait_iic_ok(chip_addr,chain,0);
            read_temp(device, reg,  data, write,chip_addr,chain);
            cgsleep_ms(1);
            ret = wait_iic_ok(chip_addr,chain,1);
            cgsleep_ms(1);
            fail_time++;
        }
        while (((ret & 0xff00) >>8 != reg || (ret & 0xff) == 0xff || (ret & 0xff) == 0x7f ) && fail_time < 2);
    }
    else
    {
        do
        {
            wait_iic_ok(chip_addr,chain,0);
            read_temp(device, reg,  data, write,chip_addr,chain);
            wait_iic_ok(chip_addr,chain,1);
            cgsleep_ms(1);
            wait_iic_ok(chip_addr,chain,0);
            read_temp(device, reg,  0, 0,chip_addr,chain);
            ret = wait_iic_ok(chip_addr,chain,1);
            cgsleep_ms(1);
            fail_time++;
        }
        while (((ret & 0xff00) >>8 != reg && (ret & 0xff) != data )&& fail_time < 2);
    }

    if (fail_time == 2)
        return 0;
    else
        return ret;
}


int8_t calibration_sensor_offset(unsigned char device,unsigned char chip_addr,int chain,unsigned chip_num)
{
    int8_t offset,middle,local;
    unsigned int ret = 0;
    ret = check_reg_temp(device, 0x11, 0xba, 1, chip_addr, chain);
    ret = check_reg_temp(device, 0x0, 0x0, 0, chip_addr, chain);
    local = ret & 0xff;
    ret = check_reg_temp(device, 0x1, 0x0, 0, chip_addr, chain);
    middle = ret & 0xff;
    offset = -70 + (local - middle);
    ret = check_reg_temp(device, 0x11, offset, 1, chip_addr, chain);
}
void read_temp_func()
{
    int i;
    unsigned int ret = 0;
    int16_t temp_top = 0;

    while(1)
    {
        temp_top = 0;
        for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                pthread_mutex_lock(&reg_read_mutex);
                ret = check_reg_temp(0x98, 0x00, 0x0, 0x0, HAVE_TEMP, i);
                if (ret != 0)
                {
                    dev->chain_asic_temp[i][2][0] = (ret & 0xff);
                    if (dev->chain_asic_temp[i][2][0] > temp_top)
                    {
                        temp_top = dev->chain_asic_temp[i][2][0];
                    }
                }

                ret = check_reg_temp(0x98, 0x01, 0x0, 0x0, HAVE_TEMP, i);
                if (ret != 0)
                {
                    dev->chain_asic_temp[i][2][1] = (ret & 0xff);
                }
            }
        }
        dev->temp_top1 = temp_top;
        sleep(1);
    }
}


void chain_inactive(unsigned char chain)
{
    unsigned char buf[5] = {0,0,0,0,5};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value;

    if(!opt_multi_version)  // fil mode
    {
        buf[0] = CHAIN_INACTIVE | COMMAND_FOR_ALL;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = CRC5(buf, 4*8 - 5);
        applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        set_BC_command_buffer(cmd_buf);

        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
    else    // vil mode
    {
        buf[0] = VIL_COMMAND_TYPE | VIL_ALL | CHAIN_INACTIVE;
        buf[1] = 0x05;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = CRC5(buf, 4*8);
        applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x, buf[4]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3], buf[4]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24;
        while (1)
        {
            ret = get_BC_write_command();
            if ((ret & 0x80000000) == 0)
                break;
            cgsleep_ms(1);
        }
        set_BC_command_buffer(cmd_buf);
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
}

void set_address(unsigned char chain, unsigned char mode, unsigned char address)
{
    unsigned char buf[4] = {0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value;

    if(!opt_multi_version)  // fil mode
    {
        buf[0] = SET_ADDRESS;
        buf[1] = address;
        buf[2] = 0;
        if (mode)   //all
            buf[0] |= COMMAND_FOR_ALL;
        buf[3] = CRC5(buf, 4*8 - 5);
        applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        set_BC_command_buffer(cmd_buf);

        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
    else    // vil mode
    {
        buf[0] = VIL_COMMAND_TYPE | SET_ADDRESS;
        buf[1] = 0x05;
        buf[2] = address;
        buf[3] = 0;
        buf[4] = CRC5(buf, 4*8);
        //applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x, buf[4]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3], buf[4]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24;
        while (1)
        {
            ret = get_BC_write_command();
            if ((ret & 0x80000000) == 0)
                break;
            cgsleep_ms(1);
        }
        set_BC_command_buffer(cmd_buf);
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (chain << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
}

int calculate_asic_number(unsigned int actual_asic_number)
{
    int i = 0;
    if(actual_asic_number == 1)
    {
        i = 1;
    }
    else if(actual_asic_number == 2)
    {
        i = 2;
    }
    else if((actual_asic_number > 2) && (actual_asic_number <= 4))
    {
        i = 4;
    }
    else if((actual_asic_number > 4) && (actual_asic_number <= 8))
    {
        i = 8;
    }
    else if((actual_asic_number > 8) && (actual_asic_number <= 16))
    {
        i = 16;
    }
    else if((actual_asic_number > 16) && (actual_asic_number <= 32))
    {
        i = 32;
    }
    else if((actual_asic_number > 32) && (actual_asic_number <= 64))
    {
        i = 64;
    }
    else if((actual_asic_number > 64) && (actual_asic_number <= 128))
    {
        i = 128;
    }
    else
    {
        applog(LOG_DEBUG,"actual_asic_number = %d, but it is error\n", actual_asic_number);
        return -1;
    }
    return i;
}

int calculate_core_number(unsigned int actual_core_number)
{
    int i = 0;
    if(actual_core_number == 1)
    {
        i = 1;
    }
    else if(actual_core_number == 2)
    {
        i = 2;
    }
    else if((actual_core_number > 2) && (actual_core_number <= 4))
    {
        i = 4;
    }
    else if((actual_core_number > 4) && (actual_core_number <= 8))
    {
        i = 8;
    }
    else if((actual_core_number > 8) && (actual_core_number <= 16))
    {
        i = 16;
    }
    else if((actual_core_number > 16) && (actual_core_number <= 32))
    {
        i = 32;
    }
    else if((actual_core_number > 32) && (actual_core_number <= 64))
    {
        i = 64;
    }
    else if((actual_core_number > 64) && (actual_core_number <= 128))
    {
        i = 128;
    }
    else
    {
        applog(LOG_DEBUG,"actual_core_number = %d, but it is error\n", actual_core_number);
        return -1;
    }
    return i;
}

void software_set_address()
{
    int temp_asic_number = 0;
    unsigned int i, j;
    unsigned char chip_addr = 0;
    unsigned char check_bit = 0;

    applog(LOG_DEBUG,"--- %s\n", __FUNCTION__);

    temp_asic_number = calculate_asic_number(dev->max_asic_num_in_one_chain);
    if(temp_asic_number <= 0)
    {
        dev->addrInterval = 0x1;
        return;
    }

    dev->addrInterval = 0x100 / temp_asic_number;
    check_bit = dev->addrInterval - 1;
    while(check_bit)
    {
        check_bit = check_bit >> 1;
        dev->check_bit++;
    }

    for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1 && dev->chain_asic_num[i] == CHAIN_ASIC_NUM)
        {
            applog(LOG_DEBUG,"%s: chain %d has %d ASIC, and addrInterval is %d\n", __FUNCTION__, i, dev->chain_asic_num[i], dev->addrInterval);

            chip_addr = 0;
            chain_inactive(i);
            cgsleep_ms(30);
            chain_inactive(i);
            cgsleep_ms(30);
            chain_inactive(i);
            cgsleep_ms(30);

            for(j = 0; j < 0x100/dev->addrInterval; j++)
            {
                set_address(i, 0, chip_addr);
                chip_addr += dev->addrInterval;
                cgsleep_ms(30);
            }
        }
    }
}

void set_asic_ticket_mask(unsigned int ticket_mask)
{
    unsigned char buf[4] = {0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value,i;
    unsigned int tm;

    tm = Swap32(ticket_mask);

    for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            //first step: send new bauddiv to ASIC, but FPGA doesn't change its bauddiv, it uses old bauddiv to send BC command to ASIC
            if(!opt_multi_version)  // fil mode
            {
                buf[0] = SET_BAUD_OPS;
                buf[1] = 0x10;
                buf[2] = ticket_mask & 0x1f;
                buf[0] |= COMMAND_FOR_ALL;
                buf[3] = CRC5(buf, 4*8 - 5);
                applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
                set_BC_command_buffer(cmd_buf);

                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
            }
            else    // vil mode
            {
                buf[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
                buf[1] = 0x09;
                buf[2] = 0;
                buf[3] = TICKET_MASK;
                buf[4] = tm & 0xff;
                buf[5] = (tm >> 8) & 0xff;
                buf[6] = (tm >> 16) & 0xff;
                buf[7] = (tm >> 24) & 0xff;
                buf[8] = CRC5(buf, 8*8);

                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
                cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
                cmd_buf[2] = buf[8]<<24;

                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
            }
        }
    }
}


#if 1

void set_baud(unsigned char bauddiv,int no_use)
{
    unsigned char buf[4] = {0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value,i;


    if(dev->baud == bauddiv)
    {
        applog(LOG_DEBUG,"%s: the setting bauddiv(%d) is the same as before\n", __FUNCTION__, bauddiv);
        return;
    }

    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            //first step: send new bauddiv to ASIC, but FPGA doesn't change its bauddiv, it uses old bauddiv to send BC command to ASIC
            if(!opt_multi_version)  // fil mode ?? opt_bitmain_new_cmd_type_vil or opt_multi_version
            {
                buf[0] = SET_BAUD_OPS;
                buf[1] = 0x10;
                buf[2] = bauddiv & 0x1f;
                buf[0] |= COMMAND_FOR_ALL;
                buf[3] = CRC5(buf, 4*8 - 5);
                applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
                set_BC_command_buffer(cmd_buf);

                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
            }
            else    // vil mode
            {
                buf[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
                buf[1] = 0x09;
                buf[2] = 0;
                buf[3] = MISC_CONTROL;
                buf[4] = 0;
                buf[5] = INV_CLKO;
                buf[6] = bauddiv & 0x1f;
                buf[7] = 0;
                buf[8] = CRC5(buf, 8*8);

                cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
                cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
                cmd_buf[2] = buf[8]<<24;
                applog(LOG_DEBUG,"%s: cmd_buf[0]=0x%x, cmd_buf[1]=0x%x, cmd_buf[2]=0x%x\n", __FUNCTION__, cmd_buf[0], cmd_buf[1], cmd_buf[2]);

                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
            }
        }
    }

    // second step: change FPGA's bauddiv
    cgsleep_us(50000);
    ret = get_BC_write_command();
    value = (ret & 0xffffffe0) | (bauddiv & 0x1f);
    set_BC_write_command(value);
    dev->baud = bauddiv;
}
#endif

void set_baud_with_addr(unsigned char bauddiv,unsigned int mode,unsigned int chip_addr,int chain,int iic,int open_core,int bottom_or_mid)
{
    unsigned char buf[9] = {0,0,0,0,0,0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0};
    unsigned int ret, value,i;
    i = chain;

    //first step: send new bauddiv to ASIC, but FPGA doesn't change its bauddiv, it uses old bauddiv to send BC command to ASIC
    if(!opt_multi_version)  // fil mode
    {
        buf[0] = SET_BAUD_OPS;
        buf[1] = 0x10;
        buf[2] = bauddiv & 0x1f;
        buf[0] |= COMMAND_FOR_ALL;
        buf[3] = CRC5(buf, 4*8 - 5);
        applog(LOG_DEBUG,"%s: buf[0]=0x%x, buf[1]=0x%x, buf[2]=0x%x, buf[3]=0x%x\n", __FUNCTION__, buf[0], buf[1], buf[2], buf[3]);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        set_BC_command_buffer(cmd_buf);

        ret = get_BC_write_command();
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
    else    // vil mode
    {
        buf[0] = VIL_COMMAND_TYPE | SET_CONFIG;
        if(mode)
            buf[0] = VIL_COMMAND_TYPE | SET_CONFIG |VIL_ALL;
        buf[1] = 0x09;
        buf[2] = chip_addr;
        buf[3] = MISC_CONTROL;
        buf[4] = 0x40;
        if(bottom_or_mid)
            buf[5] = 0x20;
        else
            buf[5] = 0x21;

        if(iic)
        {
            buf[6] = (bauddiv & 0x1f) | 0x40;
            buf[7] = 0x60;
        }
        else
        {
            buf[6] = (bauddiv & 0x1f);
            buf[7] = 0x00;
        }
        if(open_core)
            buf[6] = buf[6]| GATEBCLK;
        buf[8] = 0;
        buf[8] = CRC5(buf, 8*8);

        cmd_buf[0] = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
        cmd_buf[1] = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
        cmd_buf[2] = buf[8]<<24;

        while (1)
        {
            if (((ret = get_BC_write_command()) & 0x80000000) == 0)
                break;
            cgsleep_ms(1);
        }
        set_BC_command_buffer(cmd_buf);
        value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID| (i << 16) | (ret & 0x1f);
        set_BC_write_command(value);
    }
}


void init_uart_baud()
{
    unsigned int rBaudrate = 0, baud = 0;
    unsigned char bauddiv = 0;
    int i =0;

    rBaudrate = 1000000 * 5/3 / dev->timeout * (64*8);  //64*8 need send bit, ratio=2/3
    baud = 25000000 / rBaudrate / 8 - 1;
    baud = 1; // what now? 1 or calculated like above ???

    if(baud > MAX_BAUD_DIVIDER)
    {
        bauddiv = MAX_BAUD_DIVIDER; // (MAX_BAUD_DIVIDER default: 26)
    }
    else
    {
        bauddiv = baud; // = 1
    }

    applog(LOG_DEBUG,"%s: bauddiv = %d\n", __FUNCTION__, bauddiv);

    set_baud(bauddiv,1);
}

void set_led(bool stop)
{
    static bool blink = true;
    char cmd[100];
    blink = !blink;
    if(stop)
    {
        sprintf(cmd,"echo %d > %s", 0,GREEN_LED_DEV);
        system(cmd);
        sprintf(cmd,"echo %d > %s", (blink)?1:0,RED_LED_DEV);
        system(cmd);
    }
    else
    {
        sprintf(cmd,"echo %d > %s", 0,RED_LED_DEV);
        system(cmd);
        sprintf(cmd,"echo %d > %s", (blink)?1:0,GREEN_LED_DEV);
        system(cmd);
    }

}

void pic_heart_beat_func()
{
    int i;
    while(1)
    {
        for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i])
            {
                pthread_mutex_lock(&iic_mutex);
                pic_heart_beat_each_chain(i);
                pthread_mutex_unlock(&iic_mutex);
                cgsleep_ms(10);
            }
        }
        sleep(HEART_BEAT_TIME_GAP);
    }
}

void change_pic_voltage_old()
{
    int i;
    sleep(300);

    for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
    {
        uint8_t tmp_vol = de_voltage;
        if(dev->chain_exist[i])
        {
            while(1)
            {
                if(tmp_vol > chain_voltage[i])
                    break;
                tmp_vol += 5;

                if(tmp_vol > chain_voltage[i])
                {
                    tmp_vol = chain_voltage[i];
                }

                pthread_mutex_lock(&iic_mutex);
                set_pic_voltage(i,tmp_vol);
                pthread_mutex_unlock(&iic_mutex);
                pthread_mutex_lock(&iic_mutex);
                get_pic_voltage(i);
                pthread_mutex_unlock(&iic_mutex);
                if(tmp_vol == chain_voltage[i])
                    break;
                cgsleep_ms(100);
            }
        }
    }
}


void check_system_work()
{
    struct timeval tv_start = {0, 0}, tv_end,tv_send;
    int i = 0, j = 0;
    cgtime(&tv_end);
    copy_time(&tv_start, &tv_end);
    copy_time(&tv_send_job,&tv_send);
    bool stop = false;
    int asic_num = 0, error_asic = 0, avg_num = 0;
    while(1)
    {
        struct timeval diff;
        cgtime(&tv_end);
        cgtime(&tv_send);
        timersub(&tv_end, &tv_start, &diff);

        if (diff.tv_sec > 60)
        {
            asic_num = 0, error_asic = 0, avg_num = 0;
            for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
            {
                if(dev->chain_exist[i])
                {
                    asic_num += dev->chain_asic_num[i];
                    for(j=0; j<dev->chain_asic_num[i]; j++)
                    {
                        avg_num += dev->chain_asic_nonce[i][j];
                        applog(LOG_DEBUG,"%s: chain %d asic %d asic_nonce_num %d", __FUNCTION__, i,j,dev->chain_asic_nonce[i][j]);
                    }
                }
            }
            if (asic_num != 0)
            {
                applog(LOG_DEBUG,"%s: avg_num %d asic_num %d", __FUNCTION__, avg_num,asic_num);
                avg_num = avg_num / asic_num / 8;
            }
            else
            {
                avg_num = 1;
            }
            for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
            {
                if(dev->chain_exist[i])
                {
                    int offset = 0;

                    for(j=0; j<dev->chain_asic_num[i]; j++)
                    {
                        if(j%8 == 0)
                        {
                            dev->chain_asic_status_string[i][j+offset] = ' ';
                            offset++;
                        }

                        if(dev->chain_asic_nonce[i][j]>avg_num)
                        {
                            dev->chain_asic_status_string[i][j+offset] = 'o';
                        }
                        else
                        {
                            dev->chain_asic_status_string[i][j+offset] = 'x';
                            error_asic++;
                        }
                        dev->chain_asic_nonce[i][j] = 0;
                    }
                    dev->chain_asic_status_string[i][j+offset] = '\0';
                }
            }
            copy_time(&tv_start, &tv_end);
        }

        check_fan();
        set_PWM_according_to_temperature();
        timersub(&tv_send, &tv_send_job, &diff);

        if(diff.tv_sec > 120 || dev->temp_top1 > MAX_TEMP
           || dev->fan_num < MIN_FAN_NUM || dev->fan_speed_top1 < (MAX_FAN_SPEED * dev->fan_pwm / 150))
        {
            stop = true;

            if(dev->temp_top1 > MAX_TEMP
               || dev->fan_num < MIN_FAN_NUM || dev->fan_speed_top1 < (MAX_FAN_SPEED * dev->fan_pwm / 150))
            {
                status_error = true;
                once_error = true;

                for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
                {
                    if(dev->chain_exist[i] == 1)
                    {
                        pthread_mutex_lock(&iic_mutex);
                        disable_pic_dac(i);
                        pthread_mutex_unlock(&iic_mutex);
                    }
                }
            }
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() & ~RUN_BIT);
        }
        else
        {
            stop = false;
            if (!once_error)
                status_error = false;
        }
        if(stop_mining)
            status_error = true;
        /*
        if(error_asic > asic_num/5 || asic_num == 0)
        {
            stop = true;
        }
        */
        set_led(stop);

        cgsleep_ms(1000);
    }
}


void open_core()
{
    unsigned int i = 0, j = 0, k, m, work_id = 0, ret = 0, value = 0, work_fifo_ready = 0, loop=0;
    unsigned char gateblk[4] = {0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0}, buf[TW_WRITE_COMMAND_LEN/sizeof(unsigned int)]= {0};
    unsigned int buf_vil_tw[TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int)]= {0};
    unsigned char data[TW_WRITE_COMMAND_LEN] = {0xff};
    unsigned char buf_vil[9] = {0,0,0,0,0,0,0,0,0};
    struct vil_work work_vil;
    struct vil_work_1387 work_vil_1387;

    loop = 114;


    if(!opt_multi_version)    // fil mode
    {
        set_dhash_acc_control(get_dhash_acc_control() & (~OPERATION_MODE));
        set_hash_counting_number(0);
        gateblk[0] = SET_BAUD_OPS;
        gateblk[1] = 0;//0x10; //16-23
        gateblk[2] = dev->baud | 0x80; //8-15 gateblk=1
        gateblk[0] |= 0x80;
        //gateblk[3] = CRC5(gateblk, 4*8 - 5);
        gateblk[3] = 0x80;  // MMEN=1
        gateblk[3] = 0x80 | (0x1f & CRC5(gateblk, 4*8 - 5));
        applog(LOG_DEBUG,"%s: gateblk[0]=0x%x, gateblk[1]=0x%x, gateblk[2]=0x%x, gateblk[3]=0x%x\n", __FUNCTION__, gateblk[0], gateblk[1], gateblk[2], gateblk[3]);
        cmd_buf[0] = gateblk[0]<<24 | gateblk[1]<<16 | gateblk[2]<<8 | gateblk[3];

        memset(data, 0x00, TW_WRITE_COMMAND_LEN);
        data[TW_WRITE_COMMAND_LEN - 1] = 0xff;
        data[TW_WRITE_COMMAND_LEN - 12] = 0xff;

        for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
                cgsleep_us(10000);

                for(m=0; m<loop; m++)
                {
                    do
                    {
                        work_fifo_ready = get_buffer_space();
                        if(work_fifo_ready & (0x1 << i))
                        {
                            break;
                        }
                        else    //work fifo is full, wait for 50ms ???
                        {
                            //applog(LOG_DEBUG,"%s: chain%d work fifo not ready: 0x%x\n", __FUNCTION__, i, work_fifo_ready);
                            cgsleep_ms(50); //  wait for 50ms ?? (default: cgsleep_us(1000))
                        }
                    }
                    while(1);

                    if(m==0)    //new block
                    {
                        data[0] = NEW_BLOCK_MARKER;
                    }
                    else
                    {
                        data[0] = NORMAL_BLOCK_MARKER;
                    }

                    data[1] = i | 0x80; //set chain id and enable it

                    if(m==0)
                    {
                        ret = get_BC_write_command();   //disable null work
                        ret &= ~BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    if(m==loop - 1)
                    {
                        ret = get_BC_write_command();   //enable null work
                        ret &= (BC_COMMAND_EN_CHAIN_ID | BC_COMMAND_EN_NULL_WORK | ((i & 0xf) << 16));
                        set_BC_write_command(ret);
                    }

                    memset(buf, 0, TW_WRITE_COMMAND_LEN/sizeof(unsigned int));

                    for(j=0; j<TW_WRITE_COMMAND_LEN/sizeof(unsigned int); j++)
                    {
                        buf[j] = (data[4*j + 0] << 24) | (data[4*j + 1] << 16) | (data[4*j + 2] << 8) | data[4*j + 3];
                        if(j==9)
                        {
                            buf[j] = work_id++;
                        }
                        //applog(LOG_DEBUG,"buf[%d] = 0x%x\n", j, buf[i]);
                    }

                    set_TW_write_command(buf);
                }
            }
        }
        set_dhash_acc_control(get_dhash_acc_control() | OPERATION_MODE);
    }
    else    // vil mode // it is always set to 1 at cgminer.c (1 / true)
    {
        set_dhash_acc_control(get_dhash_acc_control() & (~OPERATION_MODE) | VIL_MODE | VIL_MIDSTATE_NUMBER(opt_multi_version));
        set_hash_counting_number(0);
        // prepare gateblk
        buf_vil[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
        buf_vil[1] = 0x09;
        buf_vil[2] = 0;
        buf_vil[3] = MISC_CONTROL;
        buf_vil[4] = 0x40;
        buf_vil[5] = INV_CLKO;  // enable INV_CLKO
        buf_vil[6] = (dev->baud & 0x1f) | GATEBCLK; // enable gateblk
        buf_vil[7] = MMEN;  // MMEN=1

        buf_vil[8] = CRC5(buf_vil, 8*8);

        cmd_buf[0] = buf_vil[0]<<24 | buf_vil[1]<<16 | buf_vil[2]<<8 | buf_vil[3];
        cmd_buf[1] = buf_vil[4]<<24 | buf_vil[5]<<16 | buf_vil[6]<<8 | buf_vil[7];
        cmd_buf[2] = buf_vil[8]<<24;

        // prepare special work for openning core
        memset(buf_vil_tw, 0x00, TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int));
        memset(&work_vil_1387, 0xff, sizeof(struct vil_work_1387));

        for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                work_vil_1387.work_type = NORMAL_BLOCK_MARKER;
                work_vil_1387.chain_id = 0x80 | i;
                work_vil_1387.reserved1[0]= 0;
                work_vil_1387.reserved1[1]= 0;
                work_vil_1387.work_count = 0;
                work_vil_1387.data[0] = 0xff;
                work_vil_1387.data[11] = 0xff;
                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
                cgsleep_us(10000);

                for(m=0; m<loop; m++)
                {
                    //applog(LOG_DEBUG,"%s: m = %d\n", __FUNCTION__, m);
                    do
                    {
                        work_fifo_ready = get_buffer_space();
                        if(work_fifo_ready & (0x1 << i))
                        {
                            break;
                        }
                        else    //work fifo is full, wait for 50ms
                        {
                            //applog(LOG_DEBUG,"%s: chain%d work fifo not ready: 0x%x\n", __FUNCTION__, i, work_fifo_ready);
                            cgsleep_us(1000);
                        }
                    }
                    while(1);

                    if(m==0)    //new block
                    {
                        work_vil_1387.work_type = NEW_BLOCK_MARKER;
                    }
                    else
                    {
                        work_vil_1387.work_type = NORMAL_BLOCK_MARKER;
                    }

                    work_vil_1387.chain_id = i | 0x80; //set chain id and enable it

                    if(m==0)
                    {
                        ret = get_BC_write_command();   //disable null work
                        ret &= ~BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    if(m==loop - 1)
                    {
                        ret = get_BC_write_command();   //enable null work
                        ret |= BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    buf_vil_tw[0] = (work_vil_1387.work_type<< 24) | (work_vil_1387.chain_id << 16) | (work_vil_1387.reserved1[0] << 8) | work_vil_1387.reserved1[1];
                    buf_vil_tw[1] = work_vil_1387.work_count;
                    for(j=2; j<DATA2_LEN/sizeof(unsigned int)+2; j++)
                    {
                        buf_vil_tw[j] = (work_vil_1387.data[4*(j-2) + 0] << 24) | (work_vil_1387.data[4*(j-2) + 1] << 16) | (work_vil_1387.data[4*(j-2) + 2] << 8) | work_vil_1387.data[4*(j-2) + 3];
                    }
                    for(j=5; j<MIDSTATE_LEN/sizeof(unsigned int)+5; j++)
                    {
                        buf_vil_tw[j] = 0;
                    }

                    set_TW_write_command_vil(buf_vil_tw);

                }
#if USE_IIC
                /*
                set_baud_with_addr(dev->baud,0,0x60,i,1,0,MID_OR_BOT);
                cgsleep_ms(10);
                set_baud_with_addr(dev->baud,0,0xa8,i,1,0,MID_OR_BOT);
                cgsleep_ms(10);
                */
                set_baud_with_addr(dev->baud,0,HAVE_TEMP,i,1,0,MID_OR_BOT);
                cgsleep_ms(10);
#endif
            }
        }
        set_dhash_acc_control(get_dhash_acc_control()| VIL_MODE | VIL_MIDSTATE_NUMBER(opt_multi_version));
    }
}

#if 0
void open_core()
{
    unsigned int i = 0, j = 0, m, work_id = 0, ret = 0, value = 0, work_fifo_ready = 0;
    unsigned char gateblk[4] = {0,0,0,0};
    unsigned int cmd_buf[3] = {0,0,0}, buf[TW_WRITE_COMMAND_LEN/sizeof(unsigned int)]= {0};
    unsigned int buf_vil_tw[TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int)]= {0};
    unsigned char data[TW_WRITE_COMMAND_LEN] = {0xff};
    unsigned char buf_vil[9] = {0};
    struct vil_work work_vil;

    if(!opt_multi_version)  // fil mode
    {
        set_dhash_acc_control(get_dhash_acc_control() & (~OPERATION_MODE));
        set_hash_counting_number(0);
        gateblk[0] = SET_BAUD_OPS;
        gateblk[1] = 0;//0x10; //16-23
        gateblk[2] = dev->baud | 0x80; //8-15 gateblk=1
        gateblk[0] |= 0x80;
        gateblk[3] = CRC5(gateblk, 4*8 - 5);
        applog(LOG_DEBUG,"%s: gateblk[0]=0x%x, gateblk[1]=0x%x, gateblk[2]=0x%x, gateblk[3]=0x%x\n", __FUNCTION__, gateblk[0], gateblk[1], gateblk[2], gateblk[3]);
        cmd_buf[0] = gateblk[0]<<24 | gateblk[1]<<16 | gateblk[2]<<8 | gateblk[3];

        memset(data, 0x00, TW_WRITE_COMMAND_LEN);
        data[TW_WRITE_COMMAND_LEN - 1] = 0xff;
        data[TW_WRITE_COMMAND_LEN - 12] = 0xff;

        for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
                cgsleep_ms(10);

                for(m=0; m<BM1385_CORE_NUM + 14; m++)  // BM1385_CORE_NUM = 50 + 14 = 64 ???
                {
                    //applog(LOG_DEBUG,"%s: m = %d\n", __FUNCTION__, m);
                    do
                    {
                        work_fifo_ready = get_buffer_space();
                        if(work_fifo_ready & (0x1 << i))
                        {
                            break;
                        }
                        else    //work fifo is full, wait for 50ms
                        {
                            //applog(LOG_DEBUG,"%s: chain%d work fifo not ready: 0x%x\n", __FUNCTION__, i, work_fifo_ready);
                            cgsleep_ms(1);
                        }
                    }
                    while(1);

                    if(m==0)    //new block
                    {
                        data[0] = NEW_BLOCK_MARKER;
                    }
                    else
                    {
                        data[0] = NORMAL_BLOCK_MARKER;
                    }

                    data[1] = i | 0x80; //set chain id and enable it

                    if(m==0)
                    {
                        ret = get_BC_write_command();   //disable null work
                        ret &= ~BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    if(m==BM1385_CORE_NUM + 14 - 1) // = 50 + 14 - 1 = 63
                    {
                        ret = get_BC_write_command();   //enable null work
                        ret |= BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    memset(buf, 0, TW_WRITE_COMMAND_LEN/sizeof(unsigned int));

                    /*
                    for(j=0; j<TW_WRITE_COMMAND_LEN; j++)
                    {
                        applog(LOG_DEBUG,"data[%d] = 0x%x\n", j, data[i]);
                    }
                    */

                    for(j=0; j<TW_WRITE_COMMAND_LEN/sizeof(unsigned int); j++)
                    {
                        buf[j] = (data[4*j + 0] << 24) | (data[4*j + 1] << 16) | (data[4*j + 2] << 8) | data[4*j + 3];
                        if(j==9)
                        {
                            buf[j] = work_id++;
                        }
                        //applog(LOG_DEBUG,"buf[%d] = 0x%x\n", j, buf[i]);
                    }

                    set_TW_write_command(buf);
                }
            }
        }
        set_dhash_acc_control(get_dhash_acc_control() | OPERATION_MODE);
    }
    else    // vil mode // for what do we need this else?
    {
        set_dhash_acc_control(get_dhash_acc_control() & (~OPERATION_MODE) | VIL_MODE | VIL_MIDSTATE_NUMBER(opt_multi_version) & (~NEW_BLOCK) & (~RUN_BIT));
        set_hash_counting_number(0);
        // prepare gateblk
        buf_vil[0] = VIL_COMMAND_TYPE | VIL_ALL | SET_CONFIG;
        buf_vil[1] = 0x09;
        buf_vil[2] = 0;
        buf_vil[3] = MISC_CONTROL;
        buf_vil[4] = 0;
        buf_vil[5] = INV_CLKO;
        buf_vil[6] = (dev->baud & 0x1f) | GATEBCLK;
        buf_vil[7] = 0;
        buf_vil[8] = CRC5(buf_vil, 8*8);

        cmd_buf[0] = buf_vil[0]<<24 | buf_vil[1]<<16 | buf_vil[2]<<8 | buf_vil[3];
        cmd_buf[1] = buf_vil[4]<<24 | buf_vil[5]<<16 | buf_vil[6]<<8 | buf_vil[7];
        cmd_buf[2] = buf_vil[8]<<24;

        // prepare special work for openning core
        memset(&work_vil, 0, sizeof(struct vil_work));
        work_vil.type = 0x01 << 5;
        work_vil.length = sizeof(struct vil_work);
        work_vil.wc_base = 0;
        work_vil.mid_num = 1;
        //work_vil.sno = 0;
        work_vil.data2[0] = 0xff;
        work_vil.data2[11] = 0xff;

        memset(data, 0x00, 4);
        memset(buf_vil_tw, 0x00, TW_WRITE_COMMAND_LEN_VIL);

        for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                set_BC_command_buffer(cmd_buf);
                ret = get_BC_write_command();
                value = BC_COMMAND_BUFFER_READY | BC_COMMAND_EN_CHAIN_ID | (i << 16) | (ret & 0x1f);
                set_BC_write_command(value);
                cgsleep_ms(10);

                for(m=0; m<BM1385_CORE_NUM + 14; m++)
                {
                    //applog(LOG_DEBUG,"%s: m = %d\n", __FUNCTION__, m);
                    do
                    {
                        work_fifo_ready = get_buffer_space();
                        if(work_fifo_ready & (0x1 << i))
                        {
                            break;
                        }
                        else    //work fifo is full, wait for 50ms
                        {
                            //applog(LOG_DEBUG,"%s: chain%d work fifo not ready: 0x%x\n", __FUNCTION__, i, work_fifo_ready);
                            cgsleep_ms(10);
                        }
                    }
                    while(1);

                    if(m==0)    //new block
                    {
                        data[0] = NEW_BLOCK_MARKER;
                    }
                    else
                    {
                        data[0] = NORMAL_BLOCK_MARKER;
                    }

                    data[1] = i | 0x80; //set chain id and enable it

                    if(m==0)
                    {
                        ret = get_BC_write_command();   //disable null work
                        ret &= ~BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    if(m==BM1385_CORE_NUM + 14 - 1)
                    {
                        ret = get_BC_write_command();   //enable null work
                        ret |= BC_COMMAND_EN_NULL_WORK;
                        set_BC_write_command(ret);
                    }

                    buf_vil_tw[0] = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
                    buf_vil_tw[1] = (work_vil.type << 24) | (work_vil.length << 16) | (work_vil.wc_base++ << 8) | work_vil.mid_num;
                    //buf_vil_tw[2] = work_vil.sno;
                    for(j=2; j<MIDSTATE_LEN/sizeof(unsigned int)+2; j++)
                    {
                        buf_vil_tw[j] = 0;
                    }
                    for(j=10; j<DATA2_LEN/sizeof(unsigned int)+10; j++)
                    {
                        buf_vil_tw[j] = (work_vil.data2[4*(j-10) + 0] << 24) | (work_vil.data2[4*(j-10) + 1] << 16) | (work_vil.data2[4*(j-10) + 2] << 8) | work_vil.data2[4*(j-10) + 3];
                    }

                    set_TW_write_command_vil(buf_vil_tw);
                }
            }
        }
        set_dhash_acc_control(get_dhash_acc_control() & (OPERATION_MODE) | VIL_MODE | VIL_MIDSTATE_NUMBER(opt_multi_version));
    }
}
#endif

void send_func()
{

    int count = 0, value, which_asic;
    int ret,i,j;
    unsigned int loop = 0, work_fifo_ready = 0, work_id = 0;

    struct work * works, *work;
    unsigned char data_fil[TW_WRITE_COMMAND_LEN] = {0xff};
    unsigned char data_vil[TW_WRITE_COMMAND_LEN_VIL] = {0xff};
    struct vil_work_1387 work_vil_1387;
    unsigned int buf[TW_WRITE_COMMAND_LEN/sizeof(unsigned int)]= {0};
    unsigned int buf_vil[TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int)]= {0};
    unsigned int number=0;
    unsigned char data[12] = {0x99,0xdb,0x00,0x19,0xa2,0x47,0x34,0x53,0x45,0x9a,0x4a,0x97};
    unsigned char midstate[32] = {0x89,0xf4,0x96,0x1a,0x80,0xfb,0xac,0x04,0xe0,0x4e,0x4c,0xbd,0xe9,0x65,0x75,0xf7,0x5e,0xbf,0x01,0x18,0xf0,0x17,0x3f,0xc4,0x43,0xea,0x24,0x5a,0x66,0xf9,0xc2,0xbd};
    unsigned char midstate_1[32] = {0xfb,0x3a,0xa2,0xe1,0xed,0xeb,0x22,0xce,0x76,0x97,0xdd,0xbc,0xa2,0x15,0x5b,0x1e,0x6b,0x92,0x9a,0xdc,0xc8,0xe0,0xdd,0xd1,0x96,0xfc,0xb3,0x37,0x30,0x75,0xa6,0x64};
    unsigned char data_1[12] = {0x99,0xdb,0x00,0x19,0x75,0x9c,0x35,0x53,0x3b,0xd5,0x31,0x20};

    memset(buf_vil, 0x0, TW_WRITE_COMMAND_LEN_VIL/sizeof(unsigned int));
    // get work for sending to asic
    //work_fil = (struct work *)((void *)cgpu.works[which_asic] + index*sizeof(struct work));

    // parse work data
    memset(&work_vil_1387, 0, sizeof(struct vil_work_1387));
    work_vil_1387.work_type = NORMAL_BLOCK_MARKER;
    work_vil_1387.chain_id = 0x80 | 0;
    work_vil_1387.reserved1[0]= 0;
    work_vil_1387.reserved1[1]= 0;
    work_vil_1387.work_count = 1;
    for(i=0; i<DATA2_LEN; i++)
    {
        work_vil_1387.data[i] = data[i];
    }
    for(i=0; i<MIDSTATE_LEN; i++)
    {
        work_vil_1387.midstate[i] = midstate[i];
    }

    // send work
    buf_vil[0] = (work_vil_1387.work_type << 24) | (work_vil_1387.chain_id << 16) | (work_vil_1387.reserved1[0] << 8) | work_vil_1387.reserved1[1];
    buf_vil[1] = work_vil_1387.work_count;
    for(j=2; j<DATA2_LEN/sizeof(int)+2; j++)
    {
        buf_vil[j] = (work_vil_1387.data[4*(j-2) + 0] << 24) | (work_vil_1387.data[4*(j-2) + 1] << 16) | (work_vil_1387.data[4*(j-2) + 2] << 8) | work_vil_1387.data[4*(j-2) + 3];
    }
    for(j=5; j<MIDSTATE_LEN/sizeof(unsigned int)+5; j++)
    {
        buf_vil[j] = (work_vil_1387.midstate[4*(j-5) + 0] << 24) | (work_vil_1387.midstate[4*(j-5) + 1] << 16) | (work_vil_1387.midstate[4*(j-5) + 2] << 8) | work_vil_1387.midstate[4*(j-5) + 3];;
    }
    set_TW_write_command_vil(buf_vil);
    //600*6ms = 3.6S
}

void get_hash_rate()
{
    while(1)
    {
        pthread_mutex_lock(&reg_read_mutex);
        check_asic_reg(0x08);
        pthread_mutex_unlock(&reg_read_mutex);
        cgsleep_ms(1000);
    }
}

void get_nonce_and_register(void)
{
    unsigned int work_id=0, *data_addr=NULL;
    unsigned int i=0, j=0, m=0, nonce_number = 0, read_loop=0;
    unsigned int buf[2] = {0,0};
    uint64_t n2h = 0, n2l = 0;
    char ret = 0;
    unsigned int nonce_p_wr=0, nonce_p_rd=0, nonce_nonce_num=0, nonce_loop_back=0;
    unsigned int reg_p_wr=0, reg_p_rd=0, reg_reg_value_num=0, reg_loop_back=0;
    char *buf_hex = NULL;

    while(1)
    {
        cgsleep_ms(10);

        i = 0;
        read_loop = 0;

        nonce_number = get_nonce_number_in_fifo() & MAX_NONCE_NUMBER_IN_FIFO;
        //applog(LOG_DEBUG,"%s: nonce_number = %d\n", __FUNCTION__, nonce_number);
        if(nonce_number)
        {
            read_loop = nonce_number;
            applog(LOG_DEBUG,"%s: read_loop = %d\n", __FUNCTION__, read_loop);

            for(j=0; j<read_loop; j++)
            {
                get_return_nonce(buf);
                if(buf[0] & WORK_ID_OR_CRC) //nonce
                {
                    if(gBegin_get_nonce)
                    {
                        if(buf[0] & NONCE_INDICATOR)
                        {
                            pthread_mutex_lock(&nonce_mutex);
                            work_id = WORK_ID_OR_CRC_VALUE(buf[0]);
                            data_addr = (unsigned int *)((unsigned char *)nonce2_jobid_address + work_id*64);
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].work_id          = work_id;
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].nonce3           = buf[1];
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].chain_num        = buf[0] & 0x0000000f;
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].job_id           = *(data_addr + JOB_ID_OFFSET);
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].header_version   = *(data_addr + HEADER_VERSION_OFFSET);
                            n2h = *(data_addr + NONCE2_H_OFFSET);
                            n2l = *(data_addr + NONCE2_L_OFFSET);
                            nonce_read_out.nonce_buffer[nonce_read_out.p_wr].nonce2           = (n2h << 32) | (n2l);

                            for(m=0; m<MIDSTATE_LEN; m++)
                            {
                                nonce_read_out.nonce_buffer[nonce_read_out.p_wr].midstate[m]  = *((unsigned char *)data_addr + MIDSTATE_OFFSET + m);
                            }

                            //applog(LOG_DEBUG,"%s: buf[0] = 0x%x\n", __FUNCTION__, buf[0]);
                            //applog(LOG_DEBUG,"%s: work_id = 0x%x\n", __FUNCTION__, work_id);
                            //applog(LOG_DEBUG,"%s: nonce2_jobid_address = 0x%x\n", __FUNCTION__, nonce2_jobid_address);
                            //applog(LOG_DEBUG,"%s: data_addr = 0x%x\n", __FUNCTION__, data_addr);
                            //applog(LOG_DEBUG,"%s: nonce3 = 0x%x\n", __FUNCTION__, nonce_read_out.nonce_buffer[nonce_read_out.p_wr].nonce3);
                            //applog(LOG_DEBUG,"%s: job_id = 0x%x\n", __FUNCTION__, nonce_read_out.nonce_buffer[nonce_read_out.p_wr].job_id);
                            //applog(LOG_DEBUG,"%s: header_version = 0x%x\n", __FUNCTION__, nonce_read_out.nonce_buffer[nonce_read_out.p_wr].header_version);
                            //applog(LOG_DEBUG,"%s: nonce2 = 0x%x\n", __FUNCTION__, nonce_read_out.nonce_buffer[nonce_read_out.p_wr].nonce2);

                            //buf_hex = bin2hex(nonce_read_out.nonce_buffer[nonce_read_out.p_wr].midstate,32);

                            //applog(LOG_DEBUG,"%s: midstate: %s\n", __FUNCTION__, buf_hex);

                            //free(buf_hex);


                            if(nonce_read_out.p_wr < MAX_NONCE_NUMBER_IN_FIFO)
                            {
                                nonce_read_out.p_wr++;
                            }
                            else
                            {
                                nonce_read_out.p_wr = 0;
                            }

                            if(nonce_read_out.nonce_num < MAX_NONCE_NUMBER_IN_FIFO)
                            {
                                nonce_read_out.nonce_num++;
                            }
                            else
                            {
                                nonce_read_out.nonce_num = MAX_NONCE_NUMBER_IN_FIFO;
                            }

                            pthread_mutex_unlock(&nonce_mutex);
                        }
                    }
                }
                else    //reg value
                {
                    if(reg_value_buf.reg_value_num >= MAX_NONCE_NUMBER_IN_FIFO || reg_value_buf.p_wr >= MAX_NONCE_NUMBER_IN_FIFO)
                    {
                        clear_register_value_buf();
                        continue;
                    }
                    pthread_mutex_lock(&reg_mutex);

                    reg_value_buf.reg_buffer[reg_value_buf.p_wr].reg_value    = buf[1];
                    reg_value_buf.reg_buffer[reg_value_buf.p_wr].crc          = (buf[0] >> 24) & 0x1f;
                    reg_value_buf.reg_buffer[reg_value_buf.p_wr].chain_number = CHAIN_NUMBER(buf[0]);

                    if(reg_value_buf.p_wr < MAX_NONCE_NUMBER_IN_FIFO )
                    {
                        reg_value_buf.p_wr++;
                    }
                    else
                    {
                        reg_value_buf.p_wr = 0;
                    }

                    if(reg_value_buf.reg_value_num < MAX_NONCE_NUMBER_IN_FIFO)
                    {
                        reg_value_buf.reg_value_num++;
                    }
                    else
                    {
                        reg_value_buf.reg_value_num = MAX_NONCE_NUMBER_IN_FIFO;
                    }
                    //applog(LOG_NOTICE,"%s: p_wr = %d reg_value_num = %d\n", __FUNCTION__,reg_value_buf.p_wr,reg_value_buf.reg_value_num);
                    pthread_mutex_unlock(&reg_mutex);
                }
            }
        }
    }
}


//interface between bmminer and axi driver
int bitmain_c5_init(struct init_config config)
{
    char ret=0,j;
    uint16_t crc = 0;
    struct init_config config_parameter;
    int i=0,x = 0,y = 0;
    int hardware_version;
    unsigned int data = 0;

    memcpy(&config_parameter, &config, sizeof(struct init_config));

    if(config_parameter.token_type != INIT_CONFIG_TYPE)
    {
        applog(LOG_DEBUG,"%s: config_parameter.token_type != 0x%x, it is 0x%x\n", __FUNCTION__, INIT_CONFIG_TYPE, config_parameter.token_type);
        return -1;
    }

    crc = CRC16((uint8_t*)(&config_parameter), sizeof(struct init_config) - sizeof(uint16_t));
    if(crc != config_parameter.crc)
    {
        applog(LOG_DEBUG,"%s: config_parameter.crc = 0x%x, but we calculate it as 0x%x\n", __FUNCTION__, config_parameter.crc, crc);
        return -2;
    }

    //malloc nonce_read_out
#if 0
    nonce_read_out = malloc(sizeof(struct nonce_buf));
    if(!nonce_read_out)
    {
        applog(LOG_DEBUG,"%s: malloc nonce_read_out failed\n", __FUNCTION__);
        return -3;
    }
    else
    {
        memset(nonce_read_out, 0, sizeof(struct nonce_buf));
        mutex_init(&nonce_read_out.spinlock);
    }

    //malloc register value buffer
    reg_value_buf = malloc(sizeof(struct reg_buf));
    if(!reg_value_buf)
    {
        applog(LOG_DEBUG,"%s: malloc reg_value_buf failed\n", __FUNCTION__);
        return -4;
    }
    else
    {
        memset(reg_value_buf, 0, sizeof(struct reg_buf));
        mutex_init(&reg_value_buf.spinlock);
    }
#endif
    read_nonce_reg_id = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(read_nonce_reg_id, NULL, get_nonce_and_register, read_nonce_reg_id))
    {
        applog(LOG_DEBUG,"%s: create thread for get nonce and register from FPGA failed\n", __FUNCTION__);
        return -5;
    }

    pthread_detach(read_nonce_reg_id->pth);

    //init axi
    bitmain_axi_init();

    //reset FPGA & HASH board
    if(config_parameter.reset)
    {
        set_QN_write_data_command(RESET_HASH_BOARD | RESET_ALL | RESET_FPGA | RESET_TIME(15));
        while(get_QN_write_data_command() & RESET_HASH_BOARD)
        {
            cgsleep_ms(30);
        }
    }
    set_nonce2_and_job_id_store_address(PHY_MEM_NONCE2_JOBID_ADDRESS);
    set_job_start_address(PHY_MEM_JOB_START_ADDRESS_1);
    //check chain
    check_chain();

    char * buf_hex = NULL;
    int board_num = 0;
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            pthread_mutex_lock(&iic_mutex);
            get_hash_board_id_number(i,hash_board_id[i]);
            buf_hex = bin2hex(hash_board_id[i],12);
            sprintf(hash_board_id_string + (board_num*id_string_len),"{\"ID\":\"%s\"},",buf_hex);
            board_num++;
            free(buf_hex);
            buf_hex = NULL;
            pthread_mutex_unlock(&iic_mutex);
        }
    }
    hash_board_id_string[board_num*id_string_len - 1] = '\0';

    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            pthread_mutex_lock(&iic_mutex);
            reset_iic_pic(i);
            cgsleep_ms(500);
            jump_to_app_from_loader(i);
            pthread_mutex_unlock(&iic_mutex);
        }
    }

#if 0
    de_voltage = opt_bitmain_c5_voltage;
    cgsleep_ms(100);
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            pthread_mutex_lock(&iic_mutex);
            chain_voltage[i] = get_pic_voltage(i);
            pthread_mutex_unlock(&iic_mutex);
        }
    }
    cgsleep_ms(100);
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            pthread_mutex_lock(&iic_mutex);
            //if(de_voltage < chain_voltage[i])
            set_pic_voltage(i,de_voltage);
            pthread_mutex_unlock(&iic_mutex);
            pthread_mutex_lock(&iic_mutex);
            get_pic_voltage(i);
            pthread_mutex_unlock(&iic_mutex);
        }
    }
    cgsleep_ms(100);
#endif
#if 0
    change_voltage_to_old = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(change_voltage_to_old, NULL, change_pic_voltage_old, change_voltage_to_old))
    {
        applog(LOG_DEBUG,"%s: create thread error for pic_heart_beat_func\n", __FUNCTION__);
        return -6;
    }
    pthread_detach(change_voltage_to_old->pth);
#endif
    pic_heart_beat = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(pic_heart_beat, NULL, pic_heart_beat_func, pic_heart_beat))
    {
        applog(LOG_DEBUG,"%s: create thread error for pic_heart_beat_func\n", __FUNCTION__);
        return -6;
    }
    pthread_detach(pic_heart_beat->pth);

    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            pthread_mutex_lock(&iic_mutex);
            enable_pic_dac(i);
            pthread_mutex_unlock(&iic_mutex);
        }
    }

    cgsleep_ms(100);

    if(config_parameter.reset)
    {
        set_QN_write_data_command(RESET_HASH_BOARD | RESET_ALL | RESET_TIME(15));
        while(get_QN_write_data_command() & RESET_HASH_BOARD)
        {
            cgsleep_ms(30);
        }
    }

    if(opt_multi_version)
        set_dhash_acc_control(get_dhash_acc_control() & (~OPERATION_MODE) | VIL_MODE | VIL_MIDSTATE_NUMBER(opt_multi_version) & (~NEW_BLOCK) & (~RUN_BIT));

    cgsleep_ms(10);
    //check ASIC number for every chain
    check_asic_reg(CHIP_ADDRESS);

    cgsleep_ms(10);
    //set core number
    dev->corenum = BM1387_CORE_NUM; // default: 114 ?? Does on chip has only 114 cores, 1385 has 50

    software_set_address();
    cgsleep_ms(10);

    check_asic_reg(CHIP_ADDRESS);
    cgsleep_ms(10);

    set_asic_ticket_mask(63);
    cgsleep_ms(10);

    if(config_parameter.frequency_eft)
    {
        dev->frequency = config_parameter.frequency;
        set_frequency(dev->frequency);
        sprintf(dev->frequency_t,"%u",dev->frequency);
    }

    cgsleep_ms(10);

    //check who control fan
    dev->fan_eft = config_parameter.fan_eft;
    dev->fan_pwm= config_parameter.fan_pwm_percent;
    applog(LOG_DEBUG,"%s: fan_eft : %d  fan_pwm : %d\n", __FUNCTION__,dev->fan_eft,dev->fan_pwm);
    if(config_parameter.fan_eft)
    {
        if((config_parameter.fan_pwm_percent >= 0) && (config_parameter.fan_pwm_percent <= 100))
        {
            set_PWM(config_parameter.fan_pwm_percent);
        }
        else
        {
            set_PWM_according_to_temperature();
        }
    }
    else
    {
        set_PWM_according_to_temperature();
    }

    //calculate real timeout
    if(config_parameter.timeout_eft)
    {
        if(config_parameter.timeout_data_integer == 0 && config_parameter.timeout_data_fractions == 0)  //driver calculate out timeout value
        {
            dev->timeout = 0x1000000 / calculate_core_number(dev->corenum) * dev->addrInterval / (dev->frequency) * 90 / 100;
            applog(LOG_DEBUG,"dev->timeout = %d\n", dev->timeout);
        }
        else
        {
            dev->timeout = config_parameter.timeout_data_integer * 1000 + config_parameter.timeout_data_fractions;
        }

        if(dev->timeout > MAX_TIMEOUT_VALUE)
        {
            dev->timeout = MAX_TIMEOUT_VALUE;
        }
    }

    //set baud
    init_uart_baud();
    cgsleep_ms(10);
#if USE_IIC
    if(access("/config/temp_sensor", 0) == -1)
    {
        system("touch /config/temp_sensor");
        for(i=0; i<BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1)
            {
                set_baud_with_addr(dev->baud,0,HAVE_TEMP,i,1,open_core,MID_OR_BOT);
            }
        }

        cgsleep_ms(5);

        for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
        {
            if(dev->chain_exist[i] == 1 && dev->chain_asic_num[i] == CHAIN_ASIC_NUM)
            {
                calibration_sensor_offset(0x98,HAVE_TEMP,i,3);
                cgsleep_ms(10);
            }
        }
    }
#endif


#if 0
    for(i=0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1 && dev->chain_asic_num[i] == CHAIN_ASIC_NUM)
        {
            set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x54,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x58,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x5c,i);
            set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x60,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x64,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x68,i);
            set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x6c,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x70,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ,0,0x74,i);
            set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x78,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x7c,i);
            //set_frequency_with_addr(dev->frequency + ADD_FREQ1,0,0x80,i);
        }
    }
#endif
    //set big timeout value for open core
    //set_time_out_control((MAX_TIMEOUT_VALUE - 100) | TIME_OUT_VALID);
    set_time_out_control(0xc350 | TIME_OUT_VALID);

    open_core();

    //set real timeout back
    if(opt_multi_version)
        set_time_out_control(((dev->timeout * opt_multi_version) & MAX_TIMEOUT_VALUE) | TIME_OUT_VALID);
    else
        set_time_out_control(((dev->timeout) & MAX_TIMEOUT_VALUE) | TIME_OUT_VALID);
    check_system_work_id = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(check_system_work_id, NULL, check_system_work, check_system_work_id))
    {
        applog(LOG_DEBUG,"%s: create thread for check system\n", __FUNCTION__);
        return -6;
    }
    pthread_detach(check_system_work_id->pth);

#if 1
    read_hash_rate = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(read_hash_rate, NULL, get_hash_rate, read_hash_rate))
    {
        applog(LOG_DEBUG,"%s: create thread for get nonce and register from FPGA failed\n", __FUNCTION__);
        return -5;
    }

    pthread_detach(read_hash_rate->pth);
#endif

#if 1
    read_temp_id = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(read_temp_id, NULL, read_temp_func, read_temp_id))
    {
        applog(LOG_DEBUG,"%s: create thread for read temp\n", __FUNCTION__);
        return -7;
    }
    pthread_detach(read_temp_id->pth);

#endif


    for(x=0; x<BITMAIN_MAX_CHAIN_NUM; x++)
    {
        if(dev->chain_exist[x])
        {
            int offset = 0;
            for(y=0; y<dev->chain_asic_num[x]; y++)
            {
                if(y%8 == 0)
                {
                    dev->chain_asic_status_string[x][y+offset] = ' ';
                    offset++;
                }
                dev->chain_asic_status_string[x][y+offset] = 'o';
                dev->chain_asic_nonce[x][y] = 0;
            }
            dev->chain_asic_status_string[x][y+offset] = '\0';
        }
    }

    hardware_version = get_hardware_version();
    pcb_version = (hardware_version >> 16) & 0x0000ffff;
    fpga_version = hardware_version & 0x000000ff;
    sprintf(g_miner_version, "%d.%d.%d.%d", fpga_version, pcb_version, C5_VERSION, 0);

    return 0;
}

int parse_job_to_c5(unsigned char **buf,struct pool *pool,uint32_t id)
{
    uint16_t crc = 0;
    uint32_t buf_len = 0;
    uint64_t nonce2 = 0;
    unsigned char * tmp_buf;
    int i;
    static uint64_t pool_send_nu = 0;
    struct part_of_job part_job;
    char *buf_hex = NULL;

    part_job.token_type         = SEND_JOB_TYPE;
    part_job.version            = 0x00;
    part_job.pool_nu            = pool_send_nu;
    part_job.new_block          = pool->swork.clean ?1:0;
    part_job.asic_diff_valid    = 1;
    part_job.asic_diff          = 15;
    part_job.job_id             = id;

    hex2bin(&part_job.bbversion, pool->bbversion, 4);
    hex2bin((uint32_t *) part_job.prev_hash, pool->prev_hash, 32);
    hex2bin(&part_job.nbit, pool->nbit, 4);
    hex2bin(&part_job.ntime, pool->ntime, 4);
    part_job.coinbase_len = pool->coinbase_len;
    part_job.nonce2_offset = pool->nonce2_offset;
    part_job.nonce2_bytes_num = pool->n2size;

    nonce2 = htole64(pool->nonce2);
    memcpy(&(part_job.nonce2_start_value), pool->coinbase + pool->nonce2_offset,8);
    memcpy(&(part_job.nonce2_start_value), &nonce2,pool->n2size);

    part_job.merkles_num = pool->merkles;
    buf_len = sizeof(struct part_of_job) + pool->coinbase_len + pool->merkles * 32 + 2;

    tmp_buf = (unsigned char *)malloc(buf_len);
    if (unlikely(!tmp_buf))
        quit(1, "Failed to malloc tmp_buf");
    part_job.length = buf_len -8;

    memset(tmp_buf,0,buf_len);
    memcpy(tmp_buf,&part_job,sizeof(struct part_of_job));
    memcpy(tmp_buf + sizeof(struct part_of_job), pool->coinbase, pool->coinbase_len);
    /*
    buf_hex = bin2hex(pool->coinbase,pool->coinbase_len);
    printf("coinbase:%s offset:%d n2size:%d nonce2%lld\n",buf_hex,pool->nonce2_offset,pool->n2size,pool->nonce2);
    free(buf_hex);
    */
    for (i = 0; i < pool->merkles; i++)
    {
        memcpy(tmp_buf + sizeof(struct part_of_job) + pool->coinbase_len + i * 32, pool->swork.merkle_bin[i], 32);
    }

    crc = CRC16((uint8_t *)tmp_buf, buf_len-2);
    memcpy(tmp_buf + (buf_len - 2), &crc, 2);

    pool_send_nu++;
    *buf = (unsigned char *)malloc(buf_len);
    if (unlikely(!tmp_buf))
        quit(1, "Failed to malloc buf");
    memcpy(*buf,tmp_buf,buf_len);
    free(tmp_buf);
    return buf_len;
}

static void show_status(int if_quit)
{
    char * buf_hex = NULL;
    unsigned int *l_job_start_address = NULL;
    unsigned int buf[2] = {0};
    int i = 0;
    get_work_nonce2(buf);
    set_dhash_acc_control((unsigned int)get_dhash_acc_control() & ~RUN_BIT);
    while((unsigned int)get_dhash_acc_control() & RUN_BIT)
    {
        cgsleep_ms(1);
        applog(LOG_DEBUG,"%s: run bit is 1 after set it to 0", __FUNCTION__);
    }

    buf_hex = bin2hex((unsigned char *)dev->current_job_start_address,c_coinbase_padding);

    free(buf_hex);
    for(i=0; i<c_merkles_num; i++)
    {
        buf_hex = bin2hex((unsigned char *)dev->current_job_start_address + c_coinbase_padding+ i*MERKLE_BIN_LEN,32);
        free(buf_hex);
    }
    if(dev->current_job_start_address == job_start_address_1)
    {
        l_job_start_address = job_start_address_2;
    }
    else if(dev->current_job_start_address == job_start_address_2)
    {
        l_job_start_address = job_start_address_1;
    }
    buf_hex = bin2hex((unsigned char *)l_job_start_address,l_coinbase_padding);
    free(buf_hex);
    for(i=0; i<l_merkles_num; i++)
    {
        buf_hex = bin2hex((unsigned char *)l_job_start_address + l_coinbase_padding+ i*MERKLE_BIN_LEN,32);
        free(buf_hex);
    }
    if(if_quit)
        quit(1, "HW is more than 5!!");
}

static void show_pool_status(struct pool *pool,uint64_t nonce2)
{
    char * buf_hex = NULL;
    int i = 0;
    buf_hex = bin2hex(pool->coinbase,pool->coinbase_len);
    printf("%s: nonce2 0x%x\n", __FUNCTION__, nonce2);
    printf("%s: coinbase : %s\n", __FUNCTION__, buf_hex);
    free(buf_hex);
    for(i=0; i<pool->merkles; i++)
    {
        buf_hex = bin2hex(pool->swork.merkle_bin[i],32);
        printf("%s: merkle_bin %d : %s\n", __FUNCTION__, i, buf_hex);
        free(buf_hex);
    }
}


int send_job(unsigned char *buf)
{
    unsigned int len = 0, i=0, j=0, coinbase_padding_len = 0;
    unsigned short int crc = 0, job_length = 0;
    unsigned char *temp_buf = NULL, *coinbase_padding = NULL, *merkles_bin = NULL;
    unsigned char buf1[PREV_HASH_LEN] = {0};
    unsigned int buf2[PREV_HASH_LEN] = {0};
    int times = 0;
    struct part_of_job *part_job = NULL;

    applog(LOG_DEBUG,"--- %s\n", __FUNCTION__);

    if(*(buf + 0) != SEND_JOB_TYPE)
    {
        applog(LOG_DEBUG,"%s: SEND_JOB_TYPE is wrong : 0x%x\n", __FUNCTION__, *(buf + 0));
        return -1;
    }

    len = *((unsigned int *)buf + 4/sizeof(int));
    applog(LOG_DEBUG,"%s: len = 0x%x\n", __FUNCTION__, len);

    temp_buf = malloc(len + 8*sizeof(unsigned char));
    if(!temp_buf)
    {
        applog(LOG_DEBUG,"%s: malloc buffer failed.\n", __FUNCTION__);
        return -2;
    }
    else
    {
        memset(temp_buf, 0, len + 8*sizeof(unsigned char));
        memcpy(temp_buf, buf, len + 8*sizeof(unsigned char));
        part_job = (struct part_of_job *)temp_buf;
    }

    //write new job data into dev->current_job_start_address
    if(dev->current_job_start_address == job_start_address_1)
    {
        dev->current_job_start_address = job_start_address_2;
    }
    else if(dev->current_job_start_address == job_start_address_2)
    {
        dev->current_job_start_address = job_start_address_1;
    }
    else
    {
        applog(LOG_DEBUG,"%s: dev->current_job_start_address = 0x%x, but job_start_address_1 = 0x%x, job_start_address_2 = 0x%x\n", __FUNCTION__, dev->current_job_start_address, job_start_address_1, job_start_address_2);
        return -3;
    }


    if((part_job->coinbase_len % 64) > 55)
    {
        coinbase_padding_len = (part_job->coinbase_len/64 + 2) * 64;
    }
    else
    {
        coinbase_padding_len = (part_job->coinbase_len/64 + 1) * 64;
    }

    coinbase_padding = malloc(coinbase_padding_len);
    if(!coinbase_padding)
    {
        applog(LOG_DEBUG,"%s: malloc coinbase_padding failed.\n", __FUNCTION__);
        return -4;
    }
    else
    {
        applog(LOG_DEBUG,"%s: coinbase_padding = 0x%x", __FUNCTION__, (unsigned int)coinbase_padding);
    }

    if(part_job->merkles_num)
    {
        merkles_bin = malloc(part_job->merkles_num * MERKLE_BIN_LEN);
        if(!merkles_bin)
        {
            applog(LOG_DEBUG,"%s: malloc merkles_bin failed.\n", __FUNCTION__);
            return -5;
        }
        else
        {
            applog(LOG_DEBUG,"%s: merkles_bin = 0x%x", __FUNCTION__, (unsigned int)merkles_bin);
        }
    }

    //applog(LOG_DEBUG,"%s: copy coinbase into memory ...\n", __FUNCTION__);
    memset(coinbase_padding, 0, coinbase_padding_len);
    memcpy(coinbase_padding, buf + sizeof(struct part_of_job), part_job->coinbase_len);
    *(coinbase_padding + part_job->coinbase_len) = 0x80;
    *((unsigned int *)coinbase_padding + (coinbase_padding_len - 4)/sizeof(int)) = Swap32((unsigned int)((unsigned long long int)(part_job->coinbase_len * sizeof(char) * 8) & 0x00000000ffffffff)); // 8 means 8 bits
    *((unsigned int *)coinbase_padding + (coinbase_padding_len - 8)/sizeof(int)) = Swap32((unsigned int)(((unsigned long long int)(part_job->coinbase_len * sizeof(char) * 8) & 0xffffffff00000000) >> 32)); // 8 means 8 bits

    l_coinbase_padding = c_coinbase_padding;
    c_coinbase_padding = coinbase_padding_len;
    for(i=0; i<coinbase_padding_len; i++)
    {
        *((unsigned char *)dev->current_job_start_address + i) = *(coinbase_padding + i);
        //applog(LOG_DEBUG,"%s: coinbase_padding_in_ddr[%d] = 0x%x", __FUNCTION__, i, *(((unsigned char *)dev->current_job_start_address + i)));
    }

    /* check coinbase & padding in ddr */
    for(i=0; i<coinbase_padding_len; i++)
    {
        if(*((unsigned char *)dev->current_job_start_address + i) != *(coinbase_padding + i))
        {
            applog(LOG_DEBUG,"%s: coinbase_padding_in_ddr[%d] = 0x%x, but *(coinbase_padding + %d) = 0x%x", __FUNCTION__, i, *(((unsigned char *)dev->current_job_start_address + i)), i, *(coinbase_padding + i));
        }
    }
    l_merkles_num = c_merkles_num;
    c_merkles_num = part_job->merkles_num;
    if(part_job->merkles_num)
    {
        applog(LOG_DEBUG,"%s: copy merkle bin into memory ...\n", __FUNCTION__);
        memset(merkles_bin, 0, part_job->merkles_num * MERKLE_BIN_LEN);
        memcpy(merkles_bin, buf + sizeof(struct part_of_job) + part_job->coinbase_len , part_job->merkles_num * MERKLE_BIN_LEN);

        for(i=0; i<(part_job->merkles_num * MERKLE_BIN_LEN); i++)
        {
            *((unsigned char *)dev->current_job_start_address + coinbase_padding_len + i) = *(merkles_bin + i);
            //applog(LOG_DEBUG,"%s: merkles_in_ddr[%d] = 0x%x", __FUNCTION__, i, *(((unsigned char *)dev->current_job_start_address + coinbase_padding_len + i)));
        }

        for(i=0; i<(part_job->merkles_num * MERKLE_BIN_LEN); i++)
        {
            if(*((unsigned char *)dev->current_job_start_address + coinbase_padding_len + i) != *(merkles_bin + i))
            {
                applog(LOG_DEBUG,"%s: merkles_in_ddr[%d] = 0x%x, but *(merkles_bin + %d) =0x%x", __FUNCTION__, i, *(((unsigned char *)dev->current_job_start_address + coinbase_padding_len + i)), i, *(merkles_bin + i));
            }
        }
    }



    set_dhash_acc_control((unsigned int)get_dhash_acc_control() & ~RUN_BIT);
    while((unsigned int)get_dhash_acc_control() & RUN_BIT)
    {
        cgsleep_ms(1);
        applog(LOG_DEBUG,"%s: run bit is 1 after set it to 0\n", __FUNCTION__);
        times++;
    }
    cgsleep_ms(1);


    //write new job data into dev->current_job_start_address
    if(dev->current_job_start_address == job_start_address_1)
    {
        set_job_start_address(PHY_MEM_JOB_START_ADDRESS_1);
        //applog(LOG_DEBUG,"%s: dev->current_job_start_address = 0x%x\n", __FUNCTION__, (unsigned int)job_start_address_2);
    }
    else if(dev->current_job_start_address == job_start_address_2)
    {
        set_job_start_address(PHY_MEM_JOB_START_ADDRESS_2);
        //applog(LOG_DEBUG,"%s: dev->current_job_start_address = 0x%x\n", __FUNCTION__, (unsigned int)job_start_address_1);
    }

    if(part_job->asic_diff_valid)
    {
        set_ticket_mask((unsigned int)(part_job->asic_diff & 0x000000ff));
        dev->diff = part_job->asic_diff & 0xff;
    }

    set_job_id(part_job->job_id);

    set_block_header_version(part_job->bbversion);

    memset(buf2, 0, PREV_HASH_LEN*sizeof(unsigned int));
    for(i=0; i<(PREV_HASH_LEN/sizeof(unsigned int)); i++)
    {
        buf2[i] = ((part_job->prev_hash[4*i + 3]) << 24) | ((part_job->prev_hash[4*i + 2]) << 16) | ((part_job->prev_hash[4*i + 1]) << 8) | (part_job->prev_hash[4*i + 0]);
    }
    set_pre_header_hash(buf2);

    set_time_stamp(part_job->ntime);

    set_target_bits(part_job->nbit);

    j = (part_job->nonce2_offset << 16) | ((unsigned char)(part_job->nonce2_bytes_num & 0x00ff)) << 8 | (unsigned char)((coinbase_padding_len/64) & 0x000000ff);
    set_coinbase_length_and_nonce2_length(j);

    //memset(buf2, 0, PREV_HASH_LEN*sizeof(unsigned int));
    buf2[0] = 0;
    buf2[1] = 0;
    buf2[0] = ((unsigned long long )(part_job->nonce2_start_value)) & 0xffffffff;
    buf2[1] = ((unsigned long long )(part_job->nonce2_start_value) >> 32) & 0xffffffff;
    set_work_nonce2(buf2);

    set_merkle_bin_number(part_job->merkles_num);

    job_length = coinbase_padding_len + part_job->merkles_num*MERKLE_BIN_LEN;
    set_job_length((unsigned int)job_length & 0x0000ffff);

    cgsleep_ms(1);


    if(!gBegin_get_nonce)
    {
        set_nonce_fifo_interrupt(get_nonce_fifo_interrupt() | FLUSH_NONCE3_FIFO);
        gBegin_get_nonce = true;
    }
#if 1
    //start FPGA generating works
    if(part_job->new_block)
    {
        if(!opt_multi_version)
        {
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | NEW_BLOCK );
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | RUN_BIT | OPERATION_MODE);
        }
        else
        {
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | NEW_BLOCK );
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | RUN_BIT | OPERATION_MODE |VIL_MODE);
        }
    }
    else
    {
        if(!opt_multi_version)
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | RUN_BIT| OPERATION_MODE );
        else
            set_dhash_acc_control((unsigned int)get_dhash_acc_control() | RUN_BIT| OPERATION_MODE |VIL_MODE);
    }
#endif

    free(temp_buf);
    free((unsigned char *)coinbase_padding);
    if(part_job->merkles_num)
    {
        free((unsigned char *)merkles_bin);
    }

    applog(LOG_DEBUG,"--- %s end\n", __FUNCTION__);
    cgtime(&tv_send_job);
    return 0;
}

static void copy_pool_stratum(struct pool *pool_stratum, struct pool *pool)
{
    int i;
    int merkles = pool->merkles;
    size_t coinbase_len = pool->coinbase_len;

    if (!pool->swork.job_id)
        return;

    cg_wlock(&pool_stratum->data_lock);
    free(pool_stratum->swork.job_id);
    free(pool_stratum->nonce1);
    free(pool_stratum->coinbase);

    align_len(&coinbase_len);
    pool_stratum->coinbase = calloc(coinbase_len, 1);
    if (unlikely(!pool_stratum->coinbase))
        quit(1, "Failed to calloc pool_stratum coinbase in c5");
    memcpy(pool_stratum->coinbase, pool->coinbase, coinbase_len);


    for (i = 0; i < pool_stratum->merkles; i++)
        free(pool_stratum->swork.merkle_bin[i]);
    if (merkles)
    {
        pool_stratum->swork.merkle_bin = realloc(pool_stratum->swork.merkle_bin,
                                                 sizeof(char *) * merkles + 1);
        for (i = 0; i < merkles; i++)
        {
            pool_stratum->swork.merkle_bin[i] = malloc(32);
            if (unlikely(!pool_stratum->swork.merkle_bin[i]))
                quit(1, "Failed to malloc pool_stratum swork merkle_bin");
            memcpy(pool_stratum->swork.merkle_bin[i], pool->swork.merkle_bin[i], 32);
        }
    }
    pool_stratum->pool_no = pool->pool_no;
    pool_stratum->sdiff = pool->sdiff;
    pool_stratum->coinbase_len = pool->coinbase_len;
    pool_stratum->nonce2_offset = pool->nonce2_offset;
    pool_stratum->n2size = pool->n2size;
    pool_stratum->merkles = pool->merkles;

    pool_stratum->swork.job_id = strdup(pool->swork.job_id);
    pool_stratum->nonce1 = strdup(pool->nonce1);

    memcpy(pool_stratum->ntime, pool->ntime, sizeof(pool_stratum->ntime));
    memcpy(pool_stratum->header_bin, pool->header_bin, sizeof(pool_stratum->header_bin));
    cg_wunlock(&pool_stratum->data_lock);
}


static void noblock_socket(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, O_NONBLOCK | flags);
}

static void block_socket(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static bool sock_connecting(void)
{
    return errno == EINPROGRESS;
}

static int get_mac(char * device,char **mac)
{
    struct ifreq ifreq;
    int sock = 0;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0)
    {
        perror("error sock");
        return 2;
    }
    strcpy(ifreq.ifr_name,device);
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) < 0)
    {
        perror("error ioctl");
        close(sock);
        return 3;
    }
    int i = 0;
    for(i = 0; i < 6; i++)
    {
        sprintf(*mac+3*i, "%02X:", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
    }
    (*mac)[strlen(*mac) - 1] = 0;
    close(sock);
    return 0;
}

static bool setup_send_mac_socket(char * s)
{
    struct addrinfo *servinfo, hints, *p;
    int sockd;
    int send_bytes,recv_bytes;
    char rec[1024];
    int flags;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(AUTH_URL, PORT, &hints, &servinfo) != 0)
    {
        return false;
    }
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockd == -1)
        {
            continue;
        }
        noblock_socket(sockd);
        if (connect(sockd, p->ai_addr, p->ai_addrlen) == -1)
        {
            struct timeval tv_timeout = {10, 0};
            int selret;
            fd_set rw;
            if (!sock_connecting())
            {
                close(sockd);
                continue;
            }
            retry:
            FD_ZERO(&rw);
            FD_SET(sockd, &rw);
            selret = select(sockd + 1, NULL, &rw, NULL, &tv_timeout);
            if  (selret > 0 && FD_ISSET(sockd, &rw))
            {
                socklen_t len;
                int err, n;

                len = sizeof(err);
                n = getsockopt(sockd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
                if (!n && !err)
                {
                    block_socket(sockd);
                    break;
                }
            }
            if (selret < 0 && interrupted())
                goto retry;
            close(sockd);
            continue;
        }
        else
        {
            block_socket(sockd);
            break;
        }
    }

    if (p == NULL)
    {
        freeaddrinfo(servinfo);
        return false;
    }

    block_socket(sockd);
    bool if_stop = false;

    int nNetTimeout=10;
    setsockopt(sockd,SOL_SOCKET,SO_SNDTIMEO,(char *)&nNetTimeout,sizeof(int));
    setsockopt(sockd,SOL_SOCKET,SO_RCVTIMEO,(char *)&nNetTimeout,sizeof(int));
    send_bytes = send(sockd,s,strlen(s),0);
    if (send_bytes != strlen(s))
    {
        if_stop = false;
    }
    memset(rec, 0, 1024);
    recv_bytes = recv(sockd, rec, 1024, 0);
    if (recv_bytes > 0)
    {
        if(strstr(rec,"false"))
            if_stop = true;
    }

    freeaddrinfo(servinfo);
    close(sockd);
    return if_stop;
}

void send_mac()
{
    char s[1024];
    static int id = 0;
    int number = 0;
    mac = (char *)malloc(sizeof(char)*32);
    get_mac("eth0",&mac);
    while(need_send)
    {
        id++;
        snprintf(s, sizeof(s),
                 "{\"ctrl_board\":\"%s\",\"id\":\"%d\",\"hashboard\":[%s]}",mac,id,hash_board_id_string);
        stop_mining = setup_send_mac_socket(s);
        if(stop_mining)
        {
            applog(LOG_NOTICE,"Stop mining!!!");
            break;
        }
        srand((unsigned) time(NULL));
        number = rand() % 600 + 60;
        sleep(number);
    }
    free(mac);
}


static bool bitmain_c5_prepare(struct thr_info *thr)
{
    struct cgpu_info *bitmain_c5 = thr->cgpu;
    struct bitmain_c5_info *info = bitmain_c5->device_data;

    info->thr = thr;
    mutex_init(&info->lock);
    cglock_init(&info->update_lock);
    cglock_init(&info->pool0.data_lock);
    cglock_init(&info->pool1.data_lock);
    cglock_init(&info->pool2.data_lock);

    struct init_config c5_config =
            {
                    .token_type = 0x51,
                    .version = 0,
                    .length = 26,
                    .reset  = 1,
                    .fan_eft = opt_bitmain_fan_ctrl,
                    .timeout_eft = 1,
                    .frequency_eft = 1,
                    .voltage_eft = 1,
                    .chain_check_time_eft  = 1,
                    .chip_config_eft         =1,
                    .hw_error_eft        =1,
                    .beeper_ctrl             =1,
                    .temp_ctrl           =1,
                    .chain_freq_eft      =1,
                    .reserved1           =0,
                    .reserved2 ={0},
                    .chain_num = 9,
                    .asic_num = 54,
                    .fan_pwm_percent = opt_bitmain_fan_pwm,
                    .temperature = 80,
                    .frequency = opt_bitmain_c5_freq,
                    .voltage = {0x07,0x25},
                    .chain_check_time_integer = 10,
                    .chain_check_time_fractions = 10,
                    .timeout_data_integer = 0,
                    .timeout_data_fractions = 0,
                    .reg_data = 0,
                    .chip_address = 0x04,
                    .reg_address= 0,
                    .chain_min_freq = 400,
                    .chain_max_freq = 600,
            };
    c5_config.crc = CRC16((uint8_t *)(&c5_config), sizeof(c5_config)-2);

    bitmain_c5_init(c5_config);

    send_mac_thr = calloc(1,sizeof(struct thr_info));
    if(thr_info_create(send_mac_thr, NULL, send_mac, send_mac_thr))
    {
        applog(LOG_DEBUG,"%s: create thread for send mac\n", __FUNCTION__);
    }

    return true;
}

static void bitmain_c5_reinit_device(struct cgpu_info *bitmain)
{
    if(!status_error)
        system("/etc/init.d/bmminer.sh restart > /dev/null 2>&1 &");
}



static void bitmain_c5_detect(__maybe_unused bool hotplug)
{
    struct cgpu_info *cgpu = calloc(1, sizeof(*cgpu));
    struct device_drv *drv = &bitmain_c5_drv;
    struct bitmain_c5_info *a;

    assert(cgpu);
    cgpu->drv = drv;
    cgpu->deven = DEV_ENABLED;
    cgpu->threads = 1;
    cgpu->device_data = calloc(sizeof(struct bitmain_c5_info), 1);
    if (unlikely(!(cgpu->device_data)))
        quit(1, "Failed to calloc cgpu_info data");
    a = cgpu->device_data;
    a->pool0_given_id = 0;
    a->pool1_given_id = 1;
    a->pool2_given_id = 2;

    assert(add_cgpu(cgpu));
}

static __inline void flip_swab(void *dest_p, const void *src_p, unsigned int length)
{
    uint32_t *dest = dest_p;
    const uint32_t *src = src_p;
    int i;

    for (i = 0; i < length/4; i++)
        dest[i] = swab32(src[i]);
}
static uint64_t hashtest_submit(struct thr_info *thr, struct work *work, uint32_t nonce, uint8_t *midstate,struct pool *pool,uint64_t nonce2,uint32_t chain_id )
{
    unsigned char hash1[32];
    unsigned char hash2[32];
    unsigned char i,j;
    unsigned char which_asic_nonce;
    uint64_t hashes = 0;
    static uint64_t pool_diff = 0, net_diff = 0;
    static uint64_t pool_diff_bit = 0, net_diff_bit = 0;

    if(pool_diff != (uint64_t)work->sdiff)
    {
        pool_diff = (uint64_t)work->sdiff;
        pool_diff_bit = 0;
        uint64_t tmp_pool_diff = pool_diff;
        while(tmp_pool_diff > 0)
        {
            tmp_pool_diff = tmp_pool_diff >> 1;
            pool_diff_bit++;
        }
        pool_diff_bit--;
        applog(LOG_DEBUG,"%s: pool_diff:%d work_diff:%d pool_diff_bit:%d ...\n", __FUNCTION__,pool_diff,work->sdiff,pool_diff_bit);
    }

    if(net_diff != (uint64_t)current_diff)
    {
        net_diff = (uint64_t)current_diff;
        net_diff_bit = 0;
        uint64_t tmp_net_diff = net_diff;
        while(tmp_net_diff > 0)
        {
            tmp_net_diff = tmp_net_diff >> 1;
            net_diff_bit++;
        }
        net_diff_bit--;
        applog(LOG_DEBUG,"%s:net_diff:%d current_diff:%d net_diff_bit %d ...\n", __FUNCTION__,net_diff,current_diff,net_diff_bit);
    }

    uint32_t *hash2_32 = (uint32_t *)hash1;
    __attribute__ ((aligned (4)))  sha2_context ctx;
    memcpy(ctx.state, (void*)work->midstate, 32);
#if TEST_DHASH
    rev((unsigned char*)ctx.state, sizeof(ctx.state));
#endif
    ctx.total[0] = 80;
    ctx.total[1] = 00;
    memcpy(hash1, (void*)work->data + 64, 12);
#if TEST_DHASH
    rev(hash1, 12);
#endif
    flip_swab(ctx.buffer, hash1, 12);
    memcpy(hash1, &nonce, 4);
#if TEST_DHASH
    rev(hash1, 4);
#endif
    flip_swab(ctx.buffer + 12, hash1, 4);

    sha2_finish(&ctx, hash1);

    memset( &ctx, 0, sizeof( sha2_context ) );
    sha2(hash1, 32, hash2);

    flip32(hash1, hash2);

    if (hash2_32[7] != 0)
    {
        if(dev->chain_exist[chain_id] == 1)
        {
            inc_hw_errors(thr);
            dev->chain_hw[chain_id]++;
        }
        //inc_hw_errors_with_diff(thr,(0x01UL << DEVICE_DIFF));
        //dev->chain_hw[chain_id]+=(0x01UL << DEVICE_DIFF);
        applog(LOG_DEBUG,"%s: HASH2_32[7] != 0", __FUNCTION__);
        return 0;
    }
    for(i=0; i < 7; i++)
    {
        if(be32toh(hash2_32[6 - i]) != 0)
            break;
    }
    if(i >= pool_diff_bit/32)
    {
        which_asic_nonce = (nonce >> (24 + dev->check_bit)) & 0xff;
        applog(LOG_DEBUG,"%s: chain %d which_asic_nonce %d ", __FUNCTION__, chain_id, which_asic_nonce);
        dev->chain_asic_nonce[chain_id][which_asic_nonce]++;
        if(be32toh(hash2_32[6 - pool_diff_bit/32]) < ((uint32_t)0xffffffff >> (pool_diff_bit%32)))
        {
            hashes += (0x01UL << DEVICE_DIFF);
            if(current_diff != 0)
            {
                for(i=0; i < net_diff_bit/32; i++)
                {
                    if(be32toh(hash2_32[6 - i]) != 0)
                        break;
                }
                if(i == net_diff_bit/32)
                {
                    if(be32toh(hash2_32[6 - net_diff_bit/32]) < ((uint32_t)0xffffffff >> (net_diff_bit%32)))
                    {
                        // to do found block!!!
                    }
                }
            }
            submit_nonce(thr, work, nonce);
        }
        else if(be32toh(hash2_32[6 - DEVICE_DIFF/32]) < ((uint32_t)0xffffffff >> (DEVICE_DIFF%32)))
        {
            hashes += (0x01UL << DEVICE_DIFF);
        }
    }
    return hashes;
}

static int64_t bitmain_scanhash(struct thr_info *thr)
{
    struct cgpu_info *bitmain_c5 = thr->cgpu;
    struct bitmain_c5_info *info = bitmain_c5->device_data;
    struct timeval current;
    double device_tdiff, hwp;
    uint32_t a = 0, b = 0;
    static uint32_t last_nonce3 = 0;
    static uint32_t last_workid = 0;
    int i, j;
    /* Stop polling the device if there is no stratum in 3 minutes, network is down */
    cgtime(&current);
    h = 0;
    pthread_mutex_lock(&nonce_mutex);
    cg_rlock(&info->update_lock);
    while(nonce_read_out.nonce_num)
    {
        uint32_t nonce3 = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].nonce3;
        uint32_t job_id = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].job_id;
        uint64_t nonce2 = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].nonce2;
        uint32_t chain_id = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].chain_num;
        uint32_t work_id = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].work_id;
        uint32_t version = Swap32(nonce_read_out.nonce_buffer[nonce_read_out.p_rd].header_version);
        uint8_t midstate[32] = {0};
        int i = 0;
        for(i=0; i<32; i++)
        {

            midstate[(7-(i/4))*4 + (i%4)] = nonce_read_out.nonce_buffer[nonce_read_out.p_rd].midstate[i];
        }
        applog(LOG_DEBUG,"%s: job_id:0x%x   work_id:0x%x   nonce2:0x%llx   nonce3:0x%x   version:0x%x\n", __FUNCTION__,job_id, work_id,nonce2, nonce3,version);
        struct work * work;

        struct pool *pool, *c_pool;
        struct pool *pool_stratum0 = &info->pool0;
        struct pool *pool_stratum1 = &info->pool1;
        struct pool *pool_stratum2 = &info->pool2;

        if(nonce_read_out.p_rd< MAX_NONCE_NUMBER_IN_FIFO)
        {
            nonce_read_out.p_rd++;
        }
        else
        {
            nonce_read_out.p_rd = 0;
        }

        nonce_read_out.nonce_num--;

        if(nonce3 != last_nonce3 || work_id != last_workid )
        {
            last_nonce3 = nonce3;
            last_workid = work_id;
        }
        else
        {
            if(dev->chain_exist[chain_id] == 1)
            {
                inc_hw_errors(thr);
                dev->chain_hw[chain_id]++;
            }
            continue;
        }

        applog(LOG_DEBUG,"%s: Chain ID J%d ...\n", __FUNCTION__, chain_id + 1);
        if( (given_id -2)> job_id && given_id < job_id)
        {
            applog(LOG_DEBUG,"%s: job_id error ...\n", __FUNCTION__);
            if(dev->chain_exist[chain_id] == 1)
            {
                inc_hw_errors(thr);
                dev->chain_hw[chain_id]++;
            }
            continue;
        }

        applog(LOG_DEBUG,"%s: given_id:%d job_id:%d switch:%d  ...\n", __FUNCTION__,given_id,job_id,given_id - job_id);

        switch (given_id - job_id)
        {
            case 0:
                pool = pool_stratum0;
                break;
            case 1:
                pool = pool_stratum1;
                break;
            case 2:
                pool = pool_stratum2;
                break;
            default:
                applog(LOG_DEBUG,"%s: job_id non't found ...\n", __FUNCTION__);
                if(dev->chain_exist[chain_id] == 1)
                {
                    inc_hw_errors(thr);
                    dev->chain_hw[chain_id]++;
                }
                continue;
        }
        c_pool = pools[pool->pool_no];
        get_work_by_nonce2(thr,&work,pool,c_pool,nonce2,pool->ntime,version);
        h += hashtest_submit(thr,work,nonce3,midstate,pool,nonce2,chain_id);
        free_work(work);
    }
    cg_runlock(&info->update_lock);
    pthread_mutex_unlock(&nonce_mutex);
    cgsleep_ms(1);
    if(h != 0)
    {
        applog(LOG_DEBUG,"%s: hashes %u ...\n", __FUNCTION__,h * 0xffffffffull);
    }
    h = h * 0xffffffffull;
}

static int64_t bitmain_c5_scanhash(struct thr_info *thr)
{
    h = 0;
    pthread_t send_id;
    pthread_create(&send_id, NULL, bitmain_scanhash, thr);
    pthread_join(send_id, NULL);
    return h;
}

static void bitmain_c5_update(struct cgpu_info *bitmain_c5)
{
    struct bitmain_c5_info *info = bitmain_c5->device_data;
    struct thr_info *thr = bitmain_c5->thr[0];
    struct work *work;
    struct pool *pool;
    int i, count = 0;
    mutex_lock(&info->lock);
    static char *last_job = NULL;
    bool same_job = true;
    unsigned char *buf = NULL;
    thr->work_update = false;
    thr->work_restart = false;
    /* Step 1: Make sure pool is ready */
    work = get_work(thr, thr->id);
    discard_work(work); /* Don't leak memory */
    /* Step 2: Protocol check */
    pool = current_pool();
    if (!pool->has_stratum)
        quit(1, "Bitmain S9 has to use stratum pools");

    /* Step 3: Parse job to c5 formart */
    cg_wlock(&info->update_lock);
    cg_rlock(&pool->data_lock);
    info->pool_no = pool->pool_no;
    copy_pool_stratum(&info->pool2, &info->pool1);
    info->pool2_given_id = info->pool1_given_id;

    copy_pool_stratum(&info->pool1, &info->pool0);
    info->pool1_given_id = info->pool0_given_id;

    copy_pool_stratum(&info->pool0, pool);
    info->pool0_given_id = ++given_id;
    parse_job_to_c5(&buf, pool, info->pool0_given_id);
    /* Step 4: Send out buf */
    if(!status_error)
        send_job(buf);
    cg_runlock(&pool->data_lock);
    cg_wunlock(&info->update_lock);
    free(buf);
    mutex_unlock(&info->lock);
}

static void get_bitmain_statline_before(char *buf, size_t bufsiz, struct cgpu_info *bitmain_c5)
{
    struct bitmain_c5_info *info = bitmain_c5->device_data;
}

static struct api_data *bitmain_api_stats(struct cgpu_info *cgpu)
{
    struct api_data *root = NULL;
    struct bitmain_c5_info *info = cgpu->device_data;
    char buf[64];
    int i = 0;
    uint64_t hash_rate_all = 0;
    char displayed_rate_all[16];
    bool copy_data = false;

    root = api_add_uint8(root,  "miner_count", &(dev->chain_num), copy_data);
    root = api_add_string(root, "frequency",   dev->frequency_t,  copy_data);
    root = api_add_uint8(root,  "fan_num",     &(dev->fan_num),   copy_data);

    for(i = 0; i < BITMAIN_MAX_FAN_NUM; i++)
    {
        char fan_name[12];
        sprintf(fan_name,"fan%d",i+1);
        root = api_add_uint(root, fan_name, &(dev->fan_speed_value[i]), copy_data);
    }

    root = api_add_uint8(root, "temp_num", &(dev->chain_num), copy_data);

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char temp_name[12];
        sprintf(temp_name,"temp%d",i+1);
        root = api_add_int16(root, temp_name, &(dev->chain_asic_temp[i][2][0]), copy_data);
    }


    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char temp2_name[12];
        sprintf(temp2_name,"temp2_%d",i+1);
        root = api_add_int16(root, temp2_name, &(dev->chain_asic_temp[i][2][1]), copy_data);
    }

    root = api_add_int(root, "temp_max", &(dev->temp_top1), copy_data);

    total_diff1 = total_diff_accepted + total_diff_rejected + total_diff_stale;

    double hwp = (hw_errors + total_diff1) ?
                 (double)(hw_errors) / (double)(hw_errors + total_diff1) : 0;

    root = api_add_percent(root, "Device Hardware%", &hwp, false);
    root = api_add_int(root,     "no_matching_work", &hw_errors, false);

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char chain_name[12];
        sprintf(chain_name,"chain_acn%d",i+1);
        root = api_add_uint8(root, chain_name, &(dev->chain_asic_num[i]), copy_data);
    }

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char chain_asic_name[12];
        sprintf(chain_asic_name,"chain_acs%d",i+1);
        root = api_add_string(root, chain_asic_name, dev->chain_asic_status_string[i], copy_data);
    }

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char chain_hw[16];
        sprintf(chain_hw,"chain_hw%d",i+1);
        root = api_add_uint32(root, chain_hw, &(dev->chain_hw[i]), copy_data);
    }

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        char chain_rate[16];
        sprintf(chain_rate,"chain_rate%d",i+1);
        root = api_add_string(root, chain_rate, &(dev->displayed_rate[i]), copy_data);
        // TODO: bug or not, test on next build: from displayed_rate[i] to &(dev->displayed_rate[i])
    }

    for(i = 0; i < BITMAIN_MAX_CHAIN_NUM; i++)
    {
        if(dev->chain_exist[i] == 1)
        {
            hash_rate_all += rate[i];
        }
    }

    suffix_string_c5(hash_rate_all, (char * )displayed_hash_rate, sizeof(displayed_hash_rate), 7,false);

    return root;
}


static void bitmain_c5_shutdown(struct thr_info *thr)
{
    unsigned int ret;
    thr_info_cancel(check_system_work_id);
    thr_info_cancel(read_nonce_reg_id);
    thr_info_cancel(read_temp_id);
    thr_info_cancel(read_hash_rate);
    thr_info_cancel(pic_heart_beat);
    thr_info_cancel(send_mac_thr);

    ret = get_BC_write_command();   //disable null work
    ret &= ~BC_COMMAND_EN_NULL_WORK;
    set_BC_write_command(ret);
    set_dhash_acc_control((unsigned int)get_dhash_acc_control() & ~RUN_BIT);
}


struct device_drv bitmain_c5_drv =
        {
                .drv_id = DRIVER_bitmain_c5,
                .dname = "Bitmain_C5",
                .name = "BC5",
                .drv_detect = bitmain_c5_detect, // 1x here and 1x cgminer.c
                .thread_prepare = bitmain_c5_prepare,
                .hash_work = hash_driver_work, // 2x here and cgminer.c
                .scanwork = bitmain_c5_scanhash,
                .flush_work = bitmain_c5_update,
                .update_work = bitmain_c5_update,
                .get_api_stats = bitmain_api_stats,
                .reinit_device = bitmain_c5_reinit_device,
                .get_statline_before = get_bitmain_statline_before,
                .thread_shutdown = bitmain_c5_shutdown,
        };

