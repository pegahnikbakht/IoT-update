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
#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "protocol_examples_common.h"
#include "errno.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#define BUFFSIZE 1012
#define HASH_LEN 32 /* SHA-256 digest length */

static const char *TAG = "native_ota_example";
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
//#define mac_calculate_offset 0
//#define mac_calculate_length 992

static char indexx[index_length] = {0xFF};
static char Enc[enc_length] = {0};
static char Hash[hash_length] = {0};
static char Mac[mac_length] = {0};
//static char Mac_calculate[mac_calculate_length] = {0};
static char previous_Hash[hash_length] = {0};
//static char calculate_Hash[252] = {0};

char *IKSW = "gv4rrcQoL3PWZG8V";
char *KSW = "uaRNrZKutHtZoplz";
char *IV = "s0fGiJWHN5FLmdd9";




extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

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

    ESP_LOG_BUFFER_HEX("HMAC_256", hmacResult, 32);

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

    ESP_LOG_BUFFER_HEX("HASH_256", shaResult, 32);
  

}


static void decrypt_symmetric(unsigned char *input, char *iv, unsigned char *output, int len)
{
    mbedtls_gcm_context aes;
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes, MBEDTLS_CIPHER_ID_AES , (const unsigned char*) KSW, strlen(KSW) * 8);
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv), NULL, 0);
    mbedtls_gcm_update(&aes,len,(const unsigned char*)input, output);
    mbedtls_gcm_free( &aes );

    ESP_LOG_BUFFER_HEX("decrypt is", output, 16);
   
    //for (int i = 0; i < 20; i++)
    //{
    //    char str[3];
    //    sprintf(str, "%c", (int)output[i]);
        //ESP_LOGI(TAG, "Decrypted value is: %s", str);
    //}
    //ESP_LOGI(TAG, "Decrypted data is: %02x", (int)output);
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

    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPG_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
    };

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

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        task_fatal_error();
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);

    update_partition = esp_ota_get_next_update_partition(NULL);
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

    int binary_file_length = 0;
    /*deal with all receive packet*/
    bool image_header_was_checked = false;
    
    int j = 0;
    int N = 148;
    const char h0[32] = {0x67,0xA3,0x2A,0xDA,0xAD,0xAA,0x5C,0x48,0x3C,0xF7,0x18,0x18,0xC5,0xDA,0x10,0x31,0xC8,0xF5,0x8D,0x9E,0x0E,0x83,0xFF,0xC2,0xA4,0xED,0xDB,0xA5,0x91,0x15,0xBB,0x84};
    int filesize = 149264;
    int lastlen = 432;
    int overheadlen = BUFFSIZE - enc_length;
    int lastEncSize = (filesize - ((N-1) * BUFFSIZE)- overheadlen);
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        
   
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            ESP_LOGI(TAG, "Read data is: %s", ota_write_data);
            //strncpy(indexx, ota_write_data + index_offset, index_length);
            memcpy(indexx, ota_write_data + index_offset, index_length);

            uint32_t IntIndex = (indexx[0] << 24) + (indexx[1] << 16) + (indexx[2] << 8) + indexx[3];
            ESP_LOGI(TAG, "index int is %d", IntIndex);
            
            int enc_index_offset = 0;
            if (IntIndex == (N - 1))
            {
                enc_index_offset = enc_length - lastEncSize;
            }

            memcpy(Enc, ota_write_data + enc_offset, enc_length-enc_index_offset);
            memcpy(Hash, ota_write_data + hash_offset-enc_index_offset, hash_length);
            memcpy(Mac, ota_write_data + mac_offset-enc_index_offset, mac_length);
            //strncpy(Mac_calculate, ota_write_data + mac_calculate_offset, mac_calculate_length);

            char hmac[32]= {0};
            unsigned char output[944] = {0};
            unsigned char outputlast[432] = {0};
             
            char hash[33] = {0};

            if(IntIndex == 0){
                hmac_256(ota_write_data, index_length + enc_length, hmac);

            }else if (IntIndex != 0)
            {
                hmac_256(ota_write_data, index_length + enc_length + hash_length - enc_index_offset, hmac);
            }
            

            ESP_LOG_BUFFER_HEX("hmac is", hmac, 32);
            ESP_LOG_BUFFER_HEX("mac is", Mac, 32);
            ESP_LOG_BUFFER_HEX("index is", ota_write_data, 4);
            ESP_LOG_BUFFER_HEX("Enc is", Enc, 64);
            ESP_LOG_BUFFER_HEX("Hash is", Hash, 32);
            //int number = (int)strtol(indexx, NULL, 0);
            ESP_LOGI(TAG, "j value is %d", j);

            if (memcmp( hmac , Mac,32) == 0 )
            {
                ESP_LOGI(TAG, "MAC checking is passed");
                //handling the right order of chunks
                if ( IntIndex == j && j == 0 ) {
                    ESP_LOGI(TAG, "Index checking of first chunk passed");
                    //check if the hashes are equal
                    hash_256(ota_write_data, index_length + enc_length - enc_index_offset, hash);
                    ESP_LOG_BUFFER_HEX("calculate hash is", hash, 32);
                    ESP_LOG_BUFFER_HEX("hash of 0 is", h0, 32);
                    
                    if (memcmp( Hash , h0,32) == 0 ){
                         ESP_LOGI(TAG, "Hash checking of first chunk is passed");
                         //decrypt E0 with KSW
                         decrypt_symmetric((unsigned char *)Enc,IV,output,enc_length);
                         //write ota_write_data in memory
                         if (image_header_was_checked == false)
                         {
                             esp_app_desc_t new_app_info;
                             if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t))
                             {
                                 // check current version with downloading
                                 memcpy(&new_app_info, &output[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                                 ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

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
                                         http_cleanup(client);
                                         infinite_loop();
                                     }
                                 }
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
                                 if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0)
                                 {
                                     ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
                                     http_cleanup(client);
                                     infinite_loop();
                                 }
#endif

                                 image_header_was_checked = true;

                                 err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
                                 if (err != ESP_OK)
                                 {
                                     ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                                     http_cleanup(client);
                                     task_fatal_error();
                                 }
                                 ESP_LOGI(TAG, "esp_ota_begin succeeded");
                             }
                             else
                             {
                                 ESP_LOGE(TAG, "received package is not fit len");
                                 http_cleanup(client);
                                 task_fatal_error();
                             }
                         }
                         err = esp_ota_write(update_handle, (const void *)output, enc_length);
                         if (err != ESP_OK)
                         {
                             http_cleanup(client);
                             task_fatal_error();
                         }
                         binary_file_length += data_read;
                         ESP_LOGD(TAG, "Written image length %d", binary_file_length);
                         j ++; 
                    }
                    //end of write data
                    else
                    {
                       break;
                    }
                    
                    memcpy(previous_Hash, hash, 32);
                }
                else if (IntIndex == j)
                {

                    ESP_LOGI(TAG, "Index checking of other chunks is passed");
                    hash_256(ota_write_data, index_length + enc_length + hash_length - enc_index_offset, hash);
                    ESP_LOG_BUFFER_HEX("calculate hash is", hash, 32);
                    ESP_LOG_BUFFER_HEX("previous hash is", previous_Hash, 32);
                    
                    if (memcmp( Hash , previous_Hash,32 ) == 0)
                    {
                        ESP_LOGI(TAG, "Hash checking of other chunks is passed");
                        //decrypt En with KSW
                        if (IntIndex == (N-1))
                        {
                            decrypt_symmetric((unsigned char *)Enc, IV, outputlast, lastlen);
                            //write ota_write_data in memory
                            err = esp_ota_write(update_handle, (const void *)outputlast, lastlen);
                        }else
                        {
                            decrypt_symmetric((unsigned char *)Enc, IV, output, enc_length);
                            //write ota_write_data in memory
                            err = esp_ota_write(update_handle, (const void *)output, enc_length);
                        }
                        
                        if (err != ESP_OK)
                        {
                            http_cleanup(client);
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
                        break;
                    }
                    memcpy(previous_Hash, hash, 32);
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
                if (esp_http_client_is_complete_data_received(client) == true)
                {
                    ESP_LOGI(TAG, "Connection closed");
                    break;
                }
            }

            if (j > (N - 1) )
            {
                ESP_LOGI(TAG, "All packets have been received and verified");
                break;
            }
        }
    }
    ESP_LOGI(TAG, "Total Write binary encrypted data length: %d", binary_file_length);
    if (esp_http_client_is_complete_data_received(client) != true) {
        ESP_LOGE(TAG, "Error in receiving complete file");
        http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        }
        ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGI(TAG, "Prepare to restart system!");
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
