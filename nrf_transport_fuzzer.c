/*
 * VELOpera nRF Firmware MQTT Transport Fuzzing Harness
 * Based on velopera-nrf-firmware/src/modules/transport/transport.c
 * 
 * Fuzzes MQTT payload processing, JSON parsing, and topic handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// Simulate velopera payload structure from real firmware
struct velopera_payload {
    char string[700];  // Real size from firmware
};

struct velopera_gps_data {
    int meas_id;
    double latitude;
    double longitude; 
    double altitude;
    double accuracy;
    double speed;
    double speed_accuracy;
    double heading;
    double pdop, hdop, vdop, tdop;
};

struct fota_filename {
    char *ptr;
    size_t size;
};

// Simulate real functions from transport.c with vulnerabilities
int modify_login_info_msg(char *msg, size_t msg_size, char *input_data, size_t input_len) {
    printf("[*] Processing login info message...\n");
    
    // Vulnerability 1: No validation of input_len vs msg_size
    if (input_len > 0) {
        // This could overflow msg buffer if input_len > msg_size
        memcpy(msg, input_data, input_len);  // BUFFER OVERFLOW!
        msg[input_len] = '\0';
    }
    
    // Vulnerability 2: Format string in snprintf (simulated)
    char format_str[100];
    if (input_len < sizeof(format_str)) {
        memcpy(format_str, input_data, input_len);
        format_str[input_len] = '\0';
        
        // If input contains format specifiers, this is vulnerable
        snprintf(msg, msg_size, format_str);  // FORMAT STRING BUG!
    }
    
    return strlen(msg);
}

// Simulate MQTT publish function with JSON processing
int process_mqtt_payload(struct velopera_payload *payload, char *input_data, size_t input_len) {
    printf("[*] Processing MQTT payload: %.50s...\n", input_data);
    
    // Vulnerability 3: Unsafe strcpy from input
    if (input_len > 0) {
        strcpy(payload->string, input_data);  // BUFFER OVERFLOW!
    }
    
    // Vulnerability 4: JSON parsing without bounds checking
    char *json_start = strstr(payload->string, "{");
    if (json_start) {
        char json_buffer[200];
        
        // Find JSON end - no bounds checking
        char *json_end = strstr(json_start, "}");
        if (json_end) {
            size_t json_len = json_end - json_start + 1;
            // Potential overflow if json_len > sizeof(json_buffer) 
            memcpy(json_buffer, json_start, json_len);  // BUFFER OVERFLOW!
            json_buffer[json_len] = '\0';
            
            printf("[*] Extracted JSON: %s\n", json_buffer);
        }
    }
    
    return 0;
}

// Simulate GPS data processing with format string vulnerability
int process_gps_data(struct velopera_gps_data *gps_data, char *input_data, size_t input_len) {
    printf("[*] Processing GPS data...\n");
    
    // Parse GPS coordinates from input (vulnerable)
    if (input_len > 20) {
        // Vulnerability 5: No validation of sscanf input
        sscanf(input_data, "%lf,%lf,%lf,%d", 
               &gps_data->latitude, 
               &gps_data->longitude,
               &gps_data->altitude,
               &gps_data->meas_id);
    }
    
    // Vulnerability 6: Format string in printf-like function
    char format_buffer[100];
    if (input_len < sizeof(format_buffer)) {
        memcpy(format_buffer, input_data, input_len);
        format_buffer[input_len] = '\0';
        
        // If input contains %s, %n, etc., this crashes
        printf(format_buffer);  // FORMAT STRING BUG!
    }
    
    return 0;
}

// Simulate FOTA filename processing
int process_fota_request(struct fota_filename *filename, char *input_data, size_t input_len) {
    printf("[*] Processing FOTA request...\n");
    
    // Vulnerability 7: Dynamic allocation without size validation
    if (input_len > 1000000) {
        // Integer overflow - wraps to small value
        size_t alloc_size = input_len * sizeof(char);
        filename->ptr = malloc(alloc_size);  // SMALL ALLOCATION!
        
        if (filename->ptr) {
            // But we copy the full input_len
            memcpy(filename->ptr, input_data, input_len);  // HEAP OVERFLOW!
            filename->size = input_len;
        }
    }
    
    // Vulnerability 8: Path traversal in filename
    char safe_path[256] = "/firmware/";
    if (input_len > 0 && input_len < 200) {
        // No validation for ../ sequences
        strncat(safe_path, input_data, input_len);  // PATH TRAVERSAL!
        printf("[*] Firmware path: %s\n", safe_path);
    }
    
    return 0;
}

// Simulate topic prefix generation (real function from transport.c)
int process_mqtt_topics(char *input_data, size_t input_len) {
    printf("[*] Processing MQTT topics...\n");
    
    char imei[16] = "123456789012345";
    char pub_topic[100];
    char sub_topic[100];
    
    // Vulnerability 9: snprintf with user-controlled format
    if (input_len > 0 && input_len < 50) {
        char topic_format[60];
        memcpy(topic_format, input_data, input_len);
        topic_format[input_len] = '\0';
        
        // If input is "ind/%s/%s%n", this can write to memory
        snprintf(pub_topic, sizeof(pub_topic), topic_format, imei, "data");  // FORMAT STRING!
        
        printf("[*] Generated topic: %s\n", pub_topic);
    }
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <mqtt_message_file>\n", argv[0]);
        printf("VELOpera nRF firmware MQTT transport fuzzer\n");
        printf("Tests: payload processing, JSON parsing, FOTA, topics\n");
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    // Read MQTT message data
    uint8_t buffer[2048];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (bytes_read == 0) {
        printf("[-] Empty input file\n");
        return 1;
    }
    
    printf("[+] Processing %zu bytes of MQTT message data\n", bytes_read);
    
    // Test different components based on first byte
    uint8_t message_type = buffer[0];
    char *test_data = (char*)(buffer + 1);
    size_t test_len = bytes_read - 1;
    
    printf("[*] Message type: 0x%02x\n", message_type);
    
    // Test different real firmware components
    switch (message_type & 0xF0) {
        case 0x00: {  // MQTT payload processing
            struct velopera_payload payload;
            printf("[*] Testing MQTT payload processing...\n");
            process_mqtt_payload(&payload, test_data, test_len);
            break;
        }
        
        case 0x10: {  // GPS data processing  
            struct velopera_gps_data gps_data;
            printf("[*] Testing GPS data processing...\n");
            process_gps_data(&gps_data, test_data, test_len);
            break;
        }
        
        case 0x20: {  // FOTA filename processing
            struct fota_filename filename;
            printf("[*] Testing FOTA request processing...\n");
            process_fota_request(&filename, test_data, test_len);
            if (filename.ptr) free(filename.ptr);
            break;
        }
        
        case 0x30: {  // Topic processing
            printf("[*] Testing MQTT topic processing...\n");
            process_mqtt_topics(test_data, test_len);
            break;
        }
        
        default: {  // Login info processing
            char login_msg[500];
            printf("[*] Testing login info processing...\n");
            modify_login_info_msg(login_msg, sizeof(login_msg), test_data, test_len);
            break;
        }
    }
    
    printf("[+] nRF firmware component testing complete\n");
    return 0;
}