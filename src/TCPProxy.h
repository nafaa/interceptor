/*
 * TCPProxy.h
 *
 *  Created on: 25 oct. 2020
 *      Author: Nafaa Zayen
 */

#ifndef TCPPROXY_H_
#define TCPPROXY_H_


#include "utility.h"
#include <sstream>
#include "HTTPURL.h"
#include "picohttpparser.h"

#include "HTTPProxy.h"

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

#include "pthread.h"

#include <sys/mman.h>
#include <sys/types.h>


//ssl
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <fstream>

#define BUF_SIZE 2097152  //16384 * 124
#define CHUNCK_SIZE 16384

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define SYNTAX_ERROR -10

#define HTTP_NEWLINE "\r\n"
#define HTTP_SPACE " "
#define HTTP_HEADER_SEPARATOR ": "



#define BACKLOG 20 // how many pending connections queue will hold


struct ThreadParam
{
	int source_sock;
	int destination_sock;
};
class TCPProxy {
public:
	void test(char  buff[],ssize_t& buflen);

	TCPProxy(char *bind_addr, int local_port,char *remote_host,int remote_port );
	virtual ~TCPProxy();

	int     check_ipversion(char * address);
	int     create_socket( );
	ssize_t Receive(char*buffer,int source_sock);
	void    Send(char*buffer,int len,int destination_sock );


	void server_loop();
	void handle_client(int client_sock, struct sockaddr_storage client_addr);
	void forward_data(int source_sock, int destination_sock);
	void forward_ext_data(int source_sock, int destination_sock);
	int create_connection();
	void update_connection_count();
	static void CreateInstance(char *bind_addr, int local_port,char *remote_host,int remote_port);
	static TCPProxy* GetInstance();
	static void DeleteInstance();

	/* media context type */
	static const char* get_media_context_type();
	const char * media_context_type_to_str();

	//thread
	static void*  forward_data_thread(void* TCPProxy );
	static void* forward_ext_data_thread(void* TCPProxy );

    //ssl
	bool is_remote_ssl(){ return is_ssl;}
	void  init_ssl();
	void  free_ssl(int socket);
	void   ShowCerts( );

	//TCP parser
	void  change_url_in_playlist(char buf[],ssize_t&  buflen ,int socket);

	static TCPProxy* s_pUniqueInst;
	int m_server_sock, m_client_sock,m_client_sock2;

private:

	char input_playlist_buffer[BUF_SIZE];
	char playlist_buffer_tosend[BUF_SIZE];
	static string     m_str_current_playlist;
	static string     m_str_current_http_url;
	string            m_str_last_http_url;
	char *m_bind_addr,*m_remote_host,*m_remote_url;

	int  m_remote_sock, m_remote_port ;
	int m_connections_processed ;

	string m_cdn_url;
	string  m_str_current_http_method;

	string  m_str_sender_current_http_method;
	string  m_str_sender_current_http_url;
	int m_local_port;
	bool is_ssl;
	MEDIA_CONTEXT_TYPE  media_context_type;

	//thread
	pthread_t   m_thread_handle;
	pthread_t   m_thread_handle_cdn;
};

#endif /* TCPPROXY_H_ */
