#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"
#include "ini.h"
#include "timeapi.h"
#pragma comment(lib, "winmm.lib")

#define MAXBUF WINDIVERT_MTU_MAX

typedef struct
{
    char* filter;
    UINT16 delay_time;
    int buffer_size;
    int priority;
    BOOL debug;
} APP_CONFIG;

typedef struct
{
    unsigned char packet[MAXBUF];
    UINT len;
    WINDIVERT_ADDRESS addr;
    DWORD timestamp;
} PACKET_SPEC;

static PACKET_SPEC packetTemp;
static PACKET_SPEC *packetRing;
static int ringHead = 0;
static int ringTail = 0;
static BOOL ctrlCPressed = FALSE;
static HANDLE hDivert, hOutputLock, hVariableLock;

static DWORD sendLoop(LPVOID pArg);

// Error handling.
static void message(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    va_end(args);
}

static void messageSafe(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    WaitForSingleObject(hOutputLock, INFINITE);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    ReleaseMutex(hOutputLock);
    va_end(args);
}

static BOOL WINAPI ctrlHandler(DWORD fdwCtrlType)
{
    if (fdwCtrlType != CTRL_C_EVENT) return FALSE;
    message("shutting down");
    WaitForSingleObject(hVariableLock, INFINITE);
    ctrlCPressed = TRUE;
    ReleaseMutex(hVariableLock);
    Sleep(500);
    return FALSE;
}

static BOOL match(const char* a, const char* b)
{
    return strcmp(a, b) == 0;
}

static int iniHandler(void* user, const char* section, const char* name, const char* value)
{
    APP_CONFIG* pConfig = (APP_CONFIG*)user;

    if (match(section, "network"))
    {
        if (match(name, "filter")) pConfig->filter = strdup(value);
        else if (match(name, "delay_time")) pConfig->delay_time = atoi(value);
        else if (match(name, "buffer_size")) pConfig->buffer_size = atoi(value);
        else if (match(name, "priority")) pConfig->priority = atoi(value);
        else return 0;
        return 1;
    }
    if (match(section, "debug"))
    {
        if (match(name, "debug")) pConfig->debug = atoi(value) != 0;
        else return 0;
        return 1;
    }
    return 0;
}

int __cdecl main(int argc, char **argv)
{
    HANDLE thread;
    APP_CONFIG appConfig = {0};

    if (ini_parse("packetdelay.ini", iniHandler, &appConfig) < 0) {
        printf("Can't load packetdelay.ini\n");
        exit(EXIT_FAILURE);
    }
    message("network.filter = %s", appConfig.filter);
    message("network.delay_time = %d", appConfig.delay_time);
    message("network.buffer_size = %d", appConfig.buffer_size);
    message("network.priority = %d", appConfig.priority);
    message("debug.debug = %d", appConfig.debug);
    message("");

    packetRing = malloc(sizeof(*packetRing) * appConfig.buffer_size);
 
    hOutputLock = CreateMutex(NULL, FALSE, NULL);
    if (hOutputLock == NULL)
    {
        message("error: failed to create mutex (%d)", GetLastError());
        exit(EXIT_FAILURE);
    }

    hVariableLock = CreateMutex(NULL, FALSE, NULL);
    if (hVariableLock == NULL)
    {
        messageSafe("error: failed to create mutex (%d)", GetLastError());
        exit(EXIT_FAILURE);
    }

    if (!SetConsoleCtrlHandler(ctrlHandler, TRUE))
    {
        messageSafe("Could not set control handler");
        exit(EXIT_FAILURE);
    }

    hDivert = WinDivertOpen(appConfig.filter, WINDIVERT_LAYER_NETWORK, appConfig.priority, 0);
    if (hDivert == INVALID_HANDLE_VALUE)
    {
        messageSafe("error: failed to open the WinDivert device (%d)", GetLastError());
        exit(EXIT_FAILURE);
    }

    thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)sendLoop, (LPVOID)&appConfig, 0, NULL);
    if (thread == NULL)
    {
        messageSafe("error: failed to create thread (%d)", GetLastError());
        exit(EXIT_FAILURE);
    }
    CloseHandle(thread);

    messageSafe("filtering started");
    messageSafe("press ctrl+c to stop");

    while (!ctrlCPressed)
    {
        if (!WinDivertRecv(hDivert, packetTemp.packet, MAXBUF, &packetTemp.len, &packetTemp.addr))
        {
            messageSafe("warning: failed to read packet (%d)", GetLastError());
            continue;
        }
        WaitForSingleObject(hVariableLock, INFINITE);
        packetRing[ringHead] = packetTemp;
        packetRing[ringHead].timestamp = timeGetTime();
        ringHead++;
        ringHead %= appConfig.buffer_size;
        ReleaseMutex(hVariableLock);
    }

    if (packetRing != NULL) free(packetRing);
    if (appConfig.filter != NULL) free(appConfig.filter);

    return 0;
}

static DWORD sendLoop(LPVOID pArg)
{
    APP_CONFIG *pConfig = (APP_CONFIG*)pArg;

    while (TRUE)
    {
        BOOL ctrlCPressedNow = FALSE;
        while (TRUE)
        {
            WaitForSingleObject(hVariableLock, INFINITE);
            ctrlCPressedNow = ctrlCPressed;
            int buffer_len = (pConfig->buffer_size + ringHead - ringTail) % pConfig->buffer_size;
            PACKET_SPEC tail = packetRing[ringTail];
            ReleaseMutex(hVariableLock);
            if (buffer_len == 0) break;

            DWORD currentTime = timeGetTime();
            DWORD deltaTime = currentTime - tail.timestamp;
            if (deltaTime < pConfig->delay_time) break;
            if (pConfig->debug) message("delta=%3d buffer_len=%d packet_len=%d", deltaTime, buffer_len, tail.len);

            WaitForSingleObject(hVariableLock, INFINITE);
            ringTail++;
            ringTail %= pConfig->buffer_size;
            ReleaseMutex(hVariableLock);
            if (!WinDivertSend(hDivert, tail.packet, tail.len, NULL, &tail.addr))
                messageSafe("warning: failed to send packet (%d)", GetLastError());
        }
        if (ctrlCPressedNow) break;
        Sleep(1);
    }
    return TRUE;
}
