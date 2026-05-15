#include <windows.h>
#include <stdio.h>
#include <string.h>

/* 
 * msgbus_pipe_probe.c - Test connectivity and probe the msgbus wire format
 * Connects to bdauxsrv pipe and tries multiple message formats
 * to identify the correct framing protocol.
 */

int test_format(HANDLE hPipe, const char* desc, byte* msg, DWORD msgLen) {
    DWORD written = 0;
    DWORD bytesRead = 0;
    byte rbuf[4096];
    
    printf("[%s] Sending %lu bytes: ", desc, msgLen);
    for (DWORD i = 0; i < (msgLen < 32 ? msgLen : 32); i++) {
        printf("%02X ", msg[i]);
    }
    printf("\n");
    
    BOOL ok = WriteFile(hPipe, msg, msgLen, &written, NULL);
    DWORD err = GetLastError();
    printf("[%s] WriteFile: ok=%d written=%lu err=%lu\n", desc, ok, written, err);
    
    if (ok && written > 0) {
        Sleep(500);
        ok = ReadFile(hPipe, rbuf, sizeof(rbuf), &bytesRead, NULL);
        err = GetLastError();
        printf("[%s] ReadFile: ok=%d bytesRead=%lu err=%lu\n", desc, ok, bytesRead, err);
        if (bytesRead > 0) {
            printf("[%s] Response: ", desc);
            for (DWORD i = 0; i < (bytesRead < 64 ? bytesRead : 64); i++) {
                printf("%02X ", rbuf[i]);
            }
            printf("\n");
            /* Try to interpret as ASCII */
            printf("[%s] ASCII: ", desc);
            for (DWORD i = 0; i < (bytesRead < 200 ? bytesRead : 200); i++) {
                if (rbuf[i] >= 0x20 && rbuf[i] <= 0x7e) printf("%c", rbuf[i]);
                else printf(".");
            }
            printf("\n");
        }
    }
    return bytesRead;
}

int wmain(int argc, wchar_t* argv[]) {
    printf("[*] msgbus_pipe_probe - Wire format probe for bdauxsrv\n\n");
    
    /* Connect to bdauxsrv pipe */
    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot connect to bdauxsrv pipe: err=%lu\n", GetLastError());
        return 1;
    }
    printf("[+] Connected to bdauxsrv pipe\n");
    
    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
    
    /* Test Format 1: u32le-length-prefixed JSON */
    {
        char json[] = "{\"module\":\"safeelevatedrun\",\"method\":\"save_regicy_value\"}";
        DWORD jsonLen = (DWORD)strlen(json);
        byte msg[256];
        *(DWORD*)msg = jsonLen;
        memcpy(msg + 4, json, jsonLen);
        /* Disconnect and reconnect since pipe might be in bad state */
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            test_format(hPipe, "u32le+JSON", msg, 4 + jsonLen);
        }
    }
    
    /* Test Format 2: Raw JSON */
    {
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            char json[] = "{\"module\":\"safeelevatedrun\",\"method\":\"save_regicy_value\"}\n";
            test_format(hPipe, "raw_json+nul", (byte*)json, (DWORD)strlen(json));
        }
    }
    
    /* Test Format 3: u32le-length + u16le-header + JSON */
    {
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            char json[] = "{\"module\":\"safeelevatedrun\",\"method\":\"save_regicy_value\"}";
            DWORD jsonLen = (DWORD)strlen(json);
            byte msg[256];
            /* Total len (4) + header_len field (2) + header_len value (2) + JSON */
            DWORD totalLen = 2 + 2 + jsonLen; /* 2 bytes header_len, 2 bytespadding, then JSON */
            *(DWORD*)msg = 4 + totalLen; /* outer length */
            *(uint16_t*)(msg+4) = (uint16_t)(4 + totalLen); /* sub-length = total */ 
            *(uint16_t*)(msg+6) = 0; /* padding/type */
            memcpy(msg + 8, json, jsonLen);
            test_format(hPipe, "u32le+u16header+JSON", msg, 8 + jsonLen);
        }
    }
    
    /* Test Format 4: flex_message-style: u32le total_len, u16le sub_len at offset 0, u16 at offset 2 */
    {
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            /* Based on RE: Buffer structure is [u32 total_len][u16 sub_struct_len][u16 payload_len][payload...] */
            char json[] = "{\"module\":\"safeelevatedrun\",\"method\":\"save_regicy_value\"}";
            DWORD jsonLen = (DWORD)strlen(json);
            byte msg[256];
            /* Sub-object: u16 sub_len(5 minimum), u16 zero, then payload_len via [2]=payload_len, payload */
            DWORD idx = 0;
            /* Outer length prefix */
            *(DWORD*)(msg + idx) = 2 + 2 + 2 + jsonLen; idx += 4;  /* total outer length */
            /* Sub-struct at param_2 + 1 (pointer to param_2[1]) */
            *(uint16_t*)(msg + idx) = (uint16_t)(2 + 2 + jsonLen); idx += 2; /* sub_struct_len */
            *(uint16_t*)(msg + idx) = (uint16_t)jsonLen; idx += 2; /* payload_len at offset [2] */
            memcpy(msg + idx, json, jsonLen); idx += jsonLen;
            test_format(hPipe, "u32le+flex(u16len+u16payload+json)", msg, idx);
        }
    }
    
    /* Test Format 5: Try byte mode (not message mode) */
    {
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            /* Try byte mode this time */
            mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            char json[] = "{\"module\":\"safeelevatedrun\",\"method\":\"save_regicy_value\"}\\x00";
            DWORD len = (DWORD)strlen(json);
            test_format(hPipe, "byte_mode+null_term_json", (byte*)json, len);
        }
    }
    
    /* Test Format 6: Try handshake first then message (uv_pipe_client style) */
    {
        CloseHandle(hPipe);
        hPipe = CreateFileW(L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            
            /* Send a "hello" - the server expects a client hello first */
            /* Per RE: handshake sends bus_name + channel info */
            byte hello[256];
            DWORD idx = 0;
            /* Total length */
            char bus_name[] = "bdauxsrv";
            char channel[] = "cl.bdauxsrv.actions";
            DWORD bus_len = (DWORD)strlen(bus_name);
            DWORD chan_len = (DWORD)strlen(channel);
            
            /* Structure: [4 bytes total_len][2 bytes sub_len][payload_len at [2]][bus_name_len u16][bus_name][chan_len u16][channel] */
            DWORD payload_size = 2 + bus_len + 2 + chan_len;
            DWORD sub_size = 2 + 2 + payload_size;
            *(DWORD*)(hello) = sub_size; idx += 4;
            *(uint16_t*)(hello + idx) = (uint16_t)sub_size; idx += 2;
            *(uint16_t*)(hello + idx) = (uint16_t)payload_size; idx += 2;
            *(uint16_t*)(hello + idx) = (uint16_t)bus_len; idx += 2;
            memcpy(hello + idx, bus_name, bus_len); idx += bus_len;
            *(uint16_t*)(hello + idx) = (uint16_t)chan_len; idx += 2;
            memcpy(hello + idx, channel, chan_len); idx += chan_len;
            
            test_format(hPipe, "handshake(bus+chan)", hello, idx);
        }
    }
    
    if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
    printf("\n[*] Probe complete\n");
    return 0;
}