/*
 * utility.h
 *
 *  Created on: 17 oct. 2020
 *      Author: nafaa
 */

#ifndef UTILITY_H_
#define UTILITY_H_

#include <stdint.h>
#include <cstddef>
#include <sstream>
#include <iostream>
using namespace std;


#if !defined(FALSE)
#define FALSE           0
#endif
#if !defined(TRUE)
#define TRUE            1
#endif

#ifdef _WIN32



#elif defined (linux)


#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif



#include <sys/time.h>
#include <sys/stat.h>
#include <assert.h>
static double  GetCurrentTimeMs(void)
{
    struct timeval _time;
    int nResult = gettimeofday(&_time, NULL);
    assert(nResult == 0);
    return ((double)(_time.tv_sec ) + (_time.tv_usec/1000000.0));

}

#include <unistd.h> /* ancienne norme */
#include <signal.h>
static bool use_syslog = FALSE;


/* Send log message to stderr or syslog */
static void  plog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if (use_syslog)
        vsyslog(priority, format, ap);
    else {
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    }

    va_end(ap);
}

/* Handle finished child process */
static void  sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}



#endif

/**
 * Extracts a selection of string and return a new string or NULL.
 * It supports both negative and positive indexes.
 */
static char *str_slice(char str[], int slice_from, int slice_to)
{
    // if a string is empty, returns nothing
    if (str[0] == '\0')
        return NULL;

    char *buffer;
    size_t str_len, buffer_len;

    // for negative indexes "slice_from" must be less "slice_to"
    if (slice_to < 0 && slice_from < slice_to) {
        str_len = strlen(str);

        // if "slice_to" goes beyond permissible limits
        if (abs(slice_to) > str_len - 1)
            return NULL;

        // if "slice_from" goes beyond permissible limits
        if (abs(slice_from) > str_len)
            slice_from = (-1) * str_len;

        buffer_len = slice_to - slice_from;
        str += (str_len + slice_from);

    // for positive indexes "slice_from" must be more "slice_to"
    } else if (slice_from >= 0 && slice_to > slice_from) {
        str_len = strlen(str);

        // if "slice_from" goes beyond permissible limits
        if (slice_from > str_len - 1)
            return NULL;

        buffer_len = slice_to - slice_from;
        str += slice_from;

    // otherwise, returns NULL
    } else
        return NULL;

    buffer =(char*) calloc(buffer_len, sizeof(char));
    strncpy(buffer, str, buffer_len);
    return buffer;
}
static  bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}
static void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

#endif /* UTILITY_H_ */
