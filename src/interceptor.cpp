//============================================================================
// Name        : interceptor.cpp
// Author      : Nafaa Zayen
// Version     : 1.0
// Copyright   :
// Description : HLS Interceptor  C++, Ansi-style
//============================================================================

#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>

#include "ExceptionHandler.h"
#include "utility.h"
#include "TCPProxy.h"
using namespace std;

int  client_sock, remote_sock, remote_port = 0;
int connections_processed = 0;
char *bind_addr, *remote_host, *cmd_in, *cmd_out;

int local_port;
bool foreground = FALSE;


/* Parse command line options */
int parse_options(int argc, char *argv[]) {
    int c ;


    while ((c = getopt(argc, argv, "b:l:h:p:fs")) != -1) {
        switch(c) {
            case 'l':
                local_port = atoi(optarg);
                break;
            case 'b':
                bind_addr = optarg;
                break;
            case 'h':
                remote_host = optarg;
                break;
            case 'p':
                remote_port = atoi(optarg);
                break;

            case 'f':
                foreground = TRUE;
                break;

            case 's':
                use_syslog = TRUE;
                break;
        }
    }

    if (local_port && remote_host && remote_port) {
        return local_port;
    } else {
        return SYNTAX_ERROR;
    }
}

int main(int argc, char **argv) {
	cout << "*****         HLS interceptor         *****" << endl;
	cout << "* -Syntax: " << argv[0]<<"-b bind_address -l local_port -h remote_host -p remote_port"<< endl;
	std::string listen_host;
	std::string stream_url;
	uint32_t    listen_port;
	foreground = TRUE;
    pid_t pid;

    bind_addr = NULL;
    int server_sock;
    local_port = parse_options(argc, argv);

    if (local_port < 0) {
        printf("Syntax: %s [-b bind_address] -l local_port -h remote_host -p remote_port   [-f (stay in foreground)] [-s (use syslog)]\n", argv[0]);
        return local_port;
    }

    if (use_syslog)
        openlog("interceptor", LOG_PID, LOG_DAEMON);


    printf("\n bind_addr %s local_port %d remote_host %s remote_port %d\n",bind_addr,local_port,remote_host,remote_port);
    TCPProxy::CreateInstance(bind_addr, local_port,remote_host,remote_port);

    if ((server_sock = TCPProxy::GetInstance()->create_socket( )) < 0) { // start server
        plog(LOG_CRIT, "Cannot run server: %m");
        printf("\n Cannot run server ");
        return server_sock;
    }

    signal(SIGCHLD,  sigchld_handler  ); // prevent ended children from becoming zombies


    TCPProxy::GetInstance()->server_loop();


    if (use_syslog)
        closelog();

    return EXIT_SUCCESS;

}
