/* OTA example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
//#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "protocol_examples_common.h"
#include "errno.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_sleep.h"

#include <sys/param.h>
#include "freertos/event_groups.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "addr_from_stdin.h"

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#define BUFFSIZE 1012
#define HASH_LEN 32 /* SHA-256 digest length */
#define HOST_IP_ADDR "192.168.0.105"
#define PORT 20001


#define MULTICAST_TTL 1

#define MULTICAST_IPV4_ADDR "232.10.11.12"

#define uS_TO_S_FACTOR 1000000  /* Conversion factor for micro seconds to seconds */
#define TIME_TO_SLEEP  13        /* Time ESP32 will go to sleep (in seconds) */


const char ant_ota[]				= "OTA start\n";
const char ant_ota_done[]			= "OTA done\n";

const char ant_dec[]				= "DEC start\n";
const char ant_dec_done[]			= "DEC done\n";

const char ant_SHA[]				= "SHA start\n";
const char ant_SHA_done[]			= "SHA done\n";

const char ant_HMAC[]				= "HMAC start\n";
const char ant_HMAC_done[]			= "HMAC done\n";

const char ant_ret[]				= "ret start\n";
const char ant_ret_done[]			= "ret done\n";

static const char *ack = "Receive done";

static const char *TAG = "ESP32_2";
/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = { 0 };


#define index_offset 0
#define index_length 4
#define enc_offset 4
#define enc_length 944
#define hash_offset 948
#define hash_length 32
#define mac_offset 980
#define mac_length 32

static char indexx[index_length] = {0xFF};
static char Enc[enc_length] = {0};
static char Hash[hash_length] = {0};
static char Mac[mac_length] = {0};
//static char Mac_calculate[mac_calculate_length] = {0};
static char next_Hash[hash_length] = {0};
//static char calculate_Hash[252] = {0};

char *IKSW = "gv4rrcQoL3PWZG8V";
char *KSW = "uaRNrZKutHtZoplzuaRNrZKutHtZoplz";
char *IV = "s0fGiJWHN5FLmdd9";


extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256


static void __attribute__((noreturn)) task_fatal_error(void)
{
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);

    while (1) {
        ;
    }
}

static void print_sha256 (const uint8_t *image_hash, const char *label)
{
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s: %s", label, hash_print);
}

static void hmac_256(const char *payload, int payloadLength, char *output)
{

    unsigned char hmacResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    const size_t keyLength = strlen(IKSW);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)IKSW, keyLength);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payload, payloadLength);
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    memcpy(output, (char *)hmacResult, 32);

    //ESP_LOG_BUFFER_HEX("HMAC_256", hmacResult, 32);

}


static void hash_256(const char *payload, int payloadLength, char *output)
{
    unsigned char shaResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);

    memcpy(output, (char *)shaResult, 32);

    //ESP_LOG_BUFFER_HEX("HASH_256", shaResult, 32);
  
}


static void decrypt_symmetric(unsigned char *input, char *iv, unsigned char *output, int len)
{
    mbedtls_gcm_context aes;
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes, MBEDTLS_CIPHER_ID_AES , (const unsigned char*) KSW, strlen(KSW) * 8);
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv), NULL, 0);
    mbedtls_gcm_update(&aes,len,(const unsigned char*)input, output);
    mbedtls_gcm_free( &aes );

    //ESP_LOG_BUFFER_HEX("decrypt is", output, 16);
   
}


void uart_init()
{
	uart_config_t uart_config = {
		.baud_rate = 115200,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
	};
	// Configure UART parameters
	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));
	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));

	gpio_config_t io_conf = {
		.pin_bit_mask	= (1ULL << 4),
		.mode			= GPIO_MODE_OUTPUT,
		.pull_up_en		= 0,
		.pull_down_en	= 1,
		.intr_type		= GPIO_PIN_INTR_DISABLE
	};

	gpio_config(&io_conf);
}

void uart_send(const char *data, size_t len)
{
#ifdef CONFIG_SQ_UART_DBG
	ESP_LOGI(TAG, "[%s] - Sending %d bytes of data: %s", __FUNCTION__, len, data);
#endif

	/* Turn on output switch for Otii, and transmit an array of bytes for annotation.
	 * Wait until TX buffer is empty, preventing bogus data to be sent.
	 */
	ESP_ERROR_CHECK(uart_wait_tx_done(UART_NUM_0, 1000));
	gpio_set_level(4, 1);
	int res = uart_write_bytes(UART_NUM_0, data, len);
	/* Again, wait until finished before turning off the output. */
	ESP_ERROR_CHECK(uart_wait_tx_done(UART_NUM_0, 1000));
	gpio_set_level(4, 0);

#ifdef CONFIG_SQ_UART_DBG
	if (res >= 0) {
		ESP_LOGI(TAG, "[%s] - Sent %d bytes of data", __FUNCTION__, res);
	} else {
		ESP_LOGI(TAG, "[%s] - Parameter error", __FUNCTION__);
	}
#endif
}


static int socket_add_ipv4_multicast_group(int sock, bool assign_source_if)
{
    struct ip_mreq imreq = { 0 };
    struct in_addr iaddr = { 0 };
    int err = 0;
    // Configure source interface
#if LISTEN_ALL_IF
    imreq.imr_interface.s_addr = IPADDR_ANY;
#else
    esp_netif_ip_info_t ip_info = { 0 };
    err = esp_netif_get_ip_info(get_example_netif(), &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get IP address info. Error 0x%x", err);
        goto err;
    }
    inet_addr_from_ip4addr(&iaddr, &ip_info.ip);
#endif // LISTEN_ALL_IF
    // Configure multicast address to listen to
    err = inet_aton(MULTICAST_IPV4_ADDR, &imreq.imr_multiaddr.s_addr);
    if (err != 1) {
        ESP_LOGE(TAG, "Configured IPV4 multicast address '%s' is invalid.", MULTICAST_IPV4_ADDR);
        // Errors in the return value have to be negative
        err = -1;
        goto err;
    }
    ESP_LOGI(TAG, "Configured IPV4 Multicast address %s", inet_ntoa(imreq.imr_multiaddr.s_addr));
    if (!IP_MULTICAST(ntohl(imreq.imr_multiaddr.s_addr))) {
        ESP_LOGW(TAG, "Configured IPV4 multicast address '%s' is not a valid multicast address. This will probably not work.", MULTICAST_IPV4_ADDR);
    }

    if (assign_source_if) {
        // Assign the IPv4 multicast source interface, via its IP
        // (only necessary if this socket is IPV4 only)
        err = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &iaddr,
                         sizeof(struct in_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Failed to set IP_MULTICAST_IF. Error %d", errno);
            goto err;
        }
    }

    err = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &imreq, sizeof(struct ip_mreq));
    if (err < 0) {
        ESP_LOGE(TAG, "Failed to set IP_ADD_MEMBERSHIP. Error %d", errno);
        goto err;
    }

 err:
    return err;
}

static void infinite_loop(void)
{
    int i = 0;
    ESP_LOGI(TAG, "When a new firmware is available on the server, press the reset button to download it");
    while(1) {
        ESP_LOGI(TAG, "Waiting for a new firmware ... %d", ++i);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

static void ota_example_task(void *pvParameter)
{
    uart_init();
    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;

    ESP_LOGI(TAG, "Starting OTA example");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (configured != running) {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);

    /*esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPG_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
    };*/

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE];
    if (strcmp(config.url, "FROM_STDIN") == 0) {
        example_configure_stdin_stdout();
        fgets(url_buf, OTA_URL_SIZE, stdin);
        int len = strlen(url_buf);
        url_buf[len - 1] = '\0';
        config.url = url_buf;
    } else {
        ESP_LOGE(TAG, "Configuration mismatch: wrong firmware upgrade image url");
        abort();
    }
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif

    
    //Unicast socket
    char host_ip[] = HOST_IP_ADDR;
    int addr_family = 0;
    int ip_protocol = 0;

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(host_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    addr_family = AF_INET;
    ip_protocol = IPPROTO_IP;

    int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        task_fatal_error();
    }
    //ESP_LOGI(TAG, "Socket created, sending to %s:%d", HOST_IP_ADDR, PORT);
    //Unicast socket 
    
    //Multicast socket
    struct sockaddr_in saddr = { 0 };
    int sockmulti = -1;
    int errm = 0;

    sockmulti = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockmulti < 0) {
        ESP_LOGE(TAG, "Failed to create socket. Error %d", errno);
        task_fatal_error();
    }
    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(PORT);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    errm = bind(sockmulti, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (errm < 0) {
        ESP_LOGE(TAG, "Failed to bind socket. Error %d", errno);
        task_fatal_error();
    }
    uint8_t ttl = MULTICAST_TTL;
    setsockopt(sockmulti, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(uint8_t));
    if (errm < 0) {
        ESP_LOGE(TAG, "Failed to set IP_MULTICAST_TTL. Error %d", errno);
        task_fatal_error();
        
    }
    errm = socket_add_ipv4_multicast_group(sockmulti, true);
    if (errm < 0) {
        task_fatal_error();
    }
    //Multicast socket

    //esp_http_client_handle_t client = esp_http_client_init(&config);
    //if (client == NULL) {
    //    ESP_LOGE(TAG, "Failed to initialise HTTP connection");
    //    task_fatal_error();
    //}
    /*err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);*/
        

    update_partition = esp_ota_get_next_update_partition(NULL);
    //ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
    //         update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

    int binary_file_length = 0;
    /*deal with all receive packet*/
    bool image_header_was_checked = false;
    
    int j = 0;
    int N = 148;
    
    //const char h0[32] = {0xE7,0xE5,0x08,0xFC,0x98,0x44,0xF2,0x8F,0x63,0x86,0x1C,0x18,0xDB,0x19,0xE6,0x3D,0xC7,0xDE,0xC8,0xB9,0x1F,0x14,0xC7,0x66,0xB4,0x2C,0x36,0xB7,0x1B,0xD7,0x0C,0x03};
    const char h0[32] = {0x51,0x64,0xD2,0x1E,0xC7,0x47,0x45,0x6C,0xD4,0x34,0x5C,0x20,0x1B,0x33,0x69,0xA5,0x68,0xD7,0x6F,0x03,0x80,0xDD,0xB0,0xC7,0x03,0x8B,0x86,0xEB,0x5E,0x9D,0x0A,0x5E};

    int filesize = 149232;
    int lastlen = 432;
    int overheadlen = BUFFSIZE - enc_length; 
    int lastEncSize = (filesize - ((N-1) * BUFFSIZE)- overheadlen);

    /* Payload maker */
    const char udp_payload[] = {"ESP32_2: alive"};
    /* Payload maker */

    struct timeval tv_now;

    int erro = sendto(sock, udp_payload, strlen(udp_payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (erro < 0)
    {
        ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
    }
    ESP_LOGI(TAG, "Message sent");

    char data_respose[32] = { 0 };
    struct sockaddr_in source_addr_uni; // Large enough for both IPv4 or IPv6
    socklen_t socklenuni = sizeof(source_addr_uni);
    int response = recvfrom(sock, data_respose, 32, 0, (struct sockaddr *)&source_addr_uni, &socklenuni);
    //ESP_LOGI(TAG, "Get response from sock uni");

    gettimeofday(&tv_now, NULL);
    int64_t time1 = (int64_t)tv_now.tv_sec * 1000000L + (int64_t)tv_now.tv_usec;
    //ESP_LOGI(TAG, "The current time is: %lld", time1);
    

    const char exp_response[] = {"NewFirmware"};

    if (response < 0)
    {
        ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
        task_fatal_error();
    }
    // Data received
    else
    {
        //ESP_LOGI(TAG, "Received %d bytes from %s:", response, host_ip);
        if (memcmp(data_respose, exp_response, strlen(exp_response)) != 0)
        {
            sleep(20);
        }
    }
    uart_send(ant_ota, sizeof(ant_ota));
    bool retransmit = false; 
    while (1) {
        //int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        //UDP read
        struct sockaddr_in source_addr; //Large enough for both IPv4 or IPv6
        socklen_t socklen = sizeof(source_addr);
        int data_read = 0;

        if (retransmit)
        {

            data_read = recvfrom(sock, ota_write_data, BUFFSIZE , 0, (struct sockaddr *)&source_addr, &socklen);
            ESP_LOGI(TAG, "Data retrasmit");
            ESP_LOGI(TAG, "Data read %d", data_read);

        }else
        {
            data_read = recvfrom(sockmulti, ota_write_data, BUFFSIZE , 0, (struct sockaddr *)&source_addr, &socklen);
        }
        
        
        

        gettimeofday(&tv_now, NULL);
        int64_t time2 = (int64_t)tv_now.tv_sec * 1000000L + (int64_t)tv_now.tv_usec;
        //ESP_LOGI(TAG, "The current time is: %lld", time2);

        if ( ((time2-time1) > 2500000 )  && retransmit == false )
        {
            retransmit = true;
            ESP_LOGI(TAG, "DoS protection enabled.");
            char retransmit_udp_payload[20] = {0};
            sprintf(retransmit_udp_payload, "ESP32_2: ret%d", j);
            uart_send(ant_ret, sizeof(ant_ret));

            sleep(13);
            //esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * uS_TO_S_FACTOR);
            //esp_deep_sleep_start();
            erro = sendto(sock, retransmit_udp_payload, strlen(retransmit_udp_payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (erro < 0)
            {
                ESP_LOGE(TAG, "Error occurred during retrasmit: errno %d", errno);
            }
            //ESP_LOGI(TAG, "retransmit sent");
            uart_send(ant_ret_done, sizeof(ant_ret_done));
   
            continue;
        }
        time1 = time2;

        // Error occurred during receiving
        if (data_read < 0)
        {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            task_fatal_error();
        }
        // Data received
        else
        {
            //ota_write_data[data_read] = 0; // Null-terminate whatever we received and treat like a string
            //ESP_LOGI(TAG, "Received %d bytes from %s:", data_read, host_ip);
            //ESP_LOG_BUFFER_HEX(TAG,ota_write_data,BUFFSIZE);
           
        }
        int err = sendto(sock, ack, strlen(ack), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0)
        {
            ESP_LOGE(TAG, "Error occurred during sending ack: errno %d", errno);
            break;
        }

        //end udp read
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            //http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            //ESP_LOGI(TAG, "Read data is: %s", ota_write_data);
            //strncpy(indexx, ota_write_data + index_offset, index_length);
            memcpy(indexx, ota_write_data + index_offset, index_length);

            uint32_t IntIndex = (indexx[0] << 24) + (indexx[1] << 16) + (indexx[2] << 8) + indexx[3];
            //ESP_LOGI(TAG, "index int is %d", IntIndex);
            
            //int enc_index_offset = 0;
            if (IntIndex == (N - 1))
            {
                //enc_index_offset = enc_length - lastEncSize -32 ;
                memcpy(Enc, ota_write_data + 4, 432);
                memcpy(Mac, ota_write_data + 436, 32);
            }else
            {
                memcpy(Enc, ota_write_data + enc_offset, enc_length);
                memcpy(Hash, ota_write_data + hash_offset, hash_length);
                memcpy(Mac, ota_write_data + mac_offset, mac_length);
            }
            

            
            //strncpy(Mac_calculate, ota_write_data + mac_calculate_offset, mac_calculate_length);

            char hmac[32]= {0};
            unsigned char output[944] = {0};
            unsigned char outputlast[468] = {0};
             
            char hash[33] = {0};
            

            if(IntIndex == (N - 1)){
                //ESP_LOG_BUFFER_HEX("Data is", hmac, 32);
                hmac_256(ota_write_data, 436, hmac);
                ESP_LOG_BUFFER_HEX("hmac is", hmac, 32);
                ESP_LOG_BUFFER_HEX("mac is", Mac, 32);
                ESP_LOG_BUFFER_HEX("index is", ota_write_data, 4);
                ESP_LOG_BUFFER_HEX("Enc is", Enc, 64);
                ESP_LOG_BUFFER_HEX("Hash is", Hash, 32);

            }else if (IntIndex != (N - 1))
            {
                //uart_send(ant_HMAC, sizeof(ant_HMAC));

                hmac_256(ota_write_data, index_length + enc_length + hash_length , hmac);
            
                //uart_send(ant_HMAC_done, sizeof(ant_HMAC_done));
                
            }
            

            
            //int number = (int)strtol(indexx, NULL, 0);
            //ESP_LOGI(TAG, "j value is %d", j);

            //ESP_LOGI(TAG, "j value is %d", j);
            if (memcmp( hmac , Mac,32) == 0 )
            {
                //ESP_LOGI(TAG, "MAC checking is passed");
                //handling the right order of chunks
                if ( IntIndex == j && j != (N-1) ) {
                    //ESP_LOGI(TAG, "Index checking of first chunk passed");
                    //check if the hashes are equal
                    //uart_send(ant_SHA, sizeof(ant_SHA));

                    hash_256(ota_write_data, index_length + enc_length + hash_length , hash);
                    //uart_send(ant_SHA_done, sizeof(ant_SHA_done));
                    
/*
                    ESP_LOG_BUFFER_HEX("calculate hash is", hash, 32);
                    ESP_LOG_BUFFER_HEX("hash of 0 is", h0, 32);
*/                  
                    if (j == 0){
                        memcpy(next_Hash, h0, 32);
                        
                    }
                    if (memcmp( hash , next_Hash,32) == 0 ){
                         //ESP_LOGI(TAG, "Hash checking of chunk is passed");
                         //decrypt E0 with KSW
                         //uart_send(ant_dec, sizeof(ant_dec));

                         decrypt_symmetric((unsigned char *)Enc,IV,output,enc_length);
                         //uart_send(ant_dec_done, sizeof(ant_dec_done));

                         //write ota_write_data in memory
                         if (image_header_was_checked == false)
                         {
                             esp_app_desc_t new_app_info;
                             if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t))
                             {
                                 // check current version with downloading
                                 memcpy(&new_app_info, &output[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                                 //ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

                                 esp_app_desc_t running_app_info;
                                 if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK)
                                 {
                                     ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
                                 }

                                 const esp_partition_t *last_invalid_app = esp_ota_get_last_invalid_partition();
                                 esp_app_desc_t invalid_app_info;
                                 if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK)
                                 {
                                     ESP_LOGI(TAG, "Last invalid firmware version: %s", invalid_app_info.version);
                                 }

                                 // check current version with last invalid partition
                                 if (last_invalid_app != NULL)
                                 {
                                     if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0)
                                     {
                                         ESP_LOGW(TAG, "New version is the same as invalid version.");
                                         ESP_LOGW(TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
                                         ESP_LOGW(TAG, "The firmware has been rolled back to the previous version.");
                                         //http_cleanup(client);
                                         infinite_loop();
                                     }
                                 }
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
                                 if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0)
                                 {
                                     ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
                                     //http_cleanup(client);
                                     infinite_loop();
                                 }
#endif

                                 image_header_was_checked = true;

                                 err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
                                 if (err != ESP_OK)
                                 {
                                     ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                                     //http_cleanup(client);
                                     task_fatal_error();
                                 }
                                 ESP_LOGI(TAG, "esp_ota_begin succeeded");
                             }
                             else
                             {
                                 ESP_LOGE(TAG, "received package is not fit len");
                                 //http_cleanup(client);
                                 task_fatal_error();
                             }
                         }
                         err = esp_ota_write(update_handle, (const void *)output, enc_length);
                         if (err != ESP_OK)
                         {
                             //http_cleanup(client);
                             task_fatal_error();
                         }
                         binary_file_length += data_read;
                         ESP_LOGD(TAG, "Written image length %d", binary_file_length);
                         j++; 
                    }
                    //end of write data
                    else
                    {     
                       char retransmit_udp_payload[20] = {0};
                       sprintf(retransmit_udp_payload,"ESP32_2: ret %d",j);
                       sleep(45);
                       erro = sendto(sock, retransmit_udp_payload, strlen(retransmit_udp_payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                       if (erro < 0)
                       {
                           ESP_LOGE(TAG, "Error occurred during retrasmit: errno %d", errno);
                       }
                       ESP_LOGI(TAG, "retransmit sent");
                    }
                    
                    memcpy(next_Hash, Hash, 32);
                }
                else if (IntIndex == (N-1))
                {

                    //ESP_LOGI(TAG, "Index checking of last chunk is passed");
                    //uart_send(ant_SHA, sizeof(ant_SHA));

                    hash_256(ota_write_data, 436, hash);
                    //uart_send(ant_SHA_done, sizeof(ant_SHA_done));
/*
                    ESP_LOG_BUFFER_HEX("calculate hash is", hash, 32);
              ESP_LOG_BUFFER_HEX("previous hash is", next_Hash, 32);
 */                   
                    if (memcmp( hash , next_Hash,32 ) == 0)
                    {
                        //ESP_LOGI(TAG, "Hash checking of last chunk is passed");
                        //decrypt En with KSW
                        // if (IntIndex == (N-1))
                        // {
                        //     //uart_send(ant_dec, sizeof(ant_dec));

                        decrypt_symmetric((unsigned char *)Enc, IV, outputlast, lastlen);
                        //uart_send(ant_dec_done, sizeof(ant_dec_done));
                            

                        //write ota_write_data in memory
                        err = esp_ota_write(update_handle, (const void *)outputlast, lastlen);
                        // }else
                        // {
                        //     //uart_send(ant_dec, sizeof(ant_dec));

                        //     decrypt_symmetric((unsigned char *)Enc, IV, output, enc_length);
                        //     //uart_send(ant_dec_done, sizeof(ant_dec_done));
                            

                        //     //write ota_write_data in memory
                        //     err = esp_ota_write(update_handle, (const void *)output, enc_length);
                        // }
                        
                        if (err != ESP_OK)
                        {
                            //http_cleanup(client);
                            task_fatal_error();
                        }
                        binary_file_length += data_read;
                        ESP_LOGD(TAG, "Written image length %d", binary_file_length);
                        j++;
                        //end of write
                    }
                    else
                    {
                       //request retransmition of the related chunk
                       char retransmit_udp_payload[20] = {0};
                       sprintf(retransmit_udp_payload,"ESP32_2: ret%d",j);
                       sleep(45);
                       erro = sendto(sock, retransmit_udp_payload, strlen(retransmit_udp_payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                       if (erro < 0)
                       {
                           ESP_LOGE(TAG, "Error occurred during retrasmit: errno %d", errno);
                       }
                       ESP_LOGI(TAG, "retransmit sent");
                    }
                    //memcpy(next_Hash, Hash, 32);
                }
            }
            else if (data_read == 0)
            {
                /*
            * As esp_http_client_read never returns negative error code, we rely on
            * `errno` to check for underlying transport connectivity closure if any
            */
                if (errno == ECONNRESET || errno == ENOTCONN)
                {
                    ESP_LOGE(TAG, "Connection closed, errno = %d", errno);
                    break;
                }
                /*if (esp_http_client_is_complete_data_received(client) == true)
                {
                    ESP_LOGI(TAG, "Connection closed");
                    break;
                }*/
            }

            if (j > (N - 1) )
            {
                ESP_LOGI(TAG, "All packets have been received and verified");
                break;
            }
        }
    }
    ESP_LOGI(TAG, "Total Write binary encrypted data length: %d", binary_file_length);
    /*if (esp_http_client_is_complete_data_received(client) != true) {
        ESP_LOGE(TAG, "Error in receiving complete file");
        http_cleanup(client);
        task_fatal_error();
    }*/

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        }
        ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        //http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        //http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGI(TAG, "Prepare to restart system!");
    uart_send(ant_ota_done, sizeof(ant_ota_done));
    esp_restart();
   
    return ;
}

static bool diagnostic(void)
{
    gpio_config_t io_conf;
    io_conf.intr_type    = GPIO_INTR_DISABLE;
    io_conf.mode         = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = (1ULL << CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en   = GPIO_PULLUP_ENABLE;
    gpio_config(&io_conf);

    ESP_LOGI(TAG, "Diagnostics (5 sec)...");
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    bool diagnostic_is_ok = gpio_get_level(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);

    gpio_reset_pin(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    return diagnostic_is_ok;
}

void app_main(void)
{

    uint8_t sha_256[HASH_LEN] = { 0 };
    esp_partition_t partition;

    // get sha256 digest for the partition table
    partition.address   = ESP_PARTITION_TABLE_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_MAX_LEN;
    partition.type      = ESP_PARTITION_TYPE_DATA;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for the partition table: ");

    // get sha256 digest for bootloader
    partition.address   = ESP_BOOTLOADER_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_OFFSET;
    partition.type      = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // run diagnostic function ...
            bool diagnostic_is_ok = diagnostic();
            if (diagnostic_is_ok) {
                ESP_LOGI(TAG, "Diagnostics completed successfully! Continuing execution ...");
                esp_ota_mark_app_valid_cancel_rollback();
            } else {
                ESP_LOGE(TAG, "Diagnostics failed! Start rollback to the previous version ...");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
    }

    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

#if CONFIG_EXAMPLE_CONNECT_WIFI
    /* Ensure to disable any WiFi power save mode, this allows best throughput
     * and hence timings for overall OTA operation.
     */
    esp_wifi_set_ps(WIFI_PS_NONE);
#endif // CONFIG_EXAMPLE_CONNECT_WIFI

    xTaskCreate(&ota_example_task, "ota_example_task", 8192, NULL, 5, NULL);
}
