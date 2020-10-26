/*
 * TCPProxy.cpp
 *
 *  Created on: 25 oct. 2020
 *      Author: Nafaa Zayen
 */

#include "TCPProxy.h"
TCPProxy* TCPProxy::s_pUniqueInst = NULL;
string TCPProxy::m_str_current_http_url = "";
string TCPProxy::m_str_current_playlist = "";

//**** shared memory ****
static double* m_send_timestamp;
static char*   current_http_url;
//ssl shared memory
static SSL *ssl;
static  const SSL_METHOD *method;
static  SSL_CTX *ctx;
// **** end of shared memory  ****/


void  sigterm_handler(int signal);

static char* GetDomain(std::string http_url, char * domain )
 {
     char* urlStr =const_cast<char*>( http_url.c_str());
     int retLen;
     if(TCPProxy::GetInstance()->is_remote_ssl())
     {
    	 retLen = sscanf(urlStr, "https://%[^/]", domain);
     }
     else
     {
    	 retLen = sscanf(urlStr, "http://%[^/]", domain);
     }

	 return domain;
}

TCPProxy::TCPProxy(char *bind_addr, int local_port,char *remote_host,int remote_port)  {

	m_bind_addr = bind_addr;
	m_local_port = local_port;
	m_remote_url = remote_host;
	m_remote_port = remote_port;
	m_connections_processed = 0;
	m_send_timestamp = (double*)  mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	current_http_url = (char*)  mmap(NULL, 100*sizeof(char), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	ssl = (SSL  *)  mmap(NULL,  sizeof(SSL *), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	method = (SSL_METHOD *)  mmap(NULL,  sizeof(SSL_METHOD *), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ctx = (SSL_CTX *)  mmap(NULL,  sizeof(SSL_CTX *), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void TCPProxy::CreateInstance(char *bind_addr, int local_port,char *remote_host,int remote_port)
{
	if(s_pUniqueInst == NULL)
	{
		s_pUniqueInst = new TCPProxy(bind_addr, local_port,remote_host, remote_port);
	}
}

TCPProxy::~TCPProxy()
{
	DeleteInstance();
}
TCPProxy* TCPProxy::GetInstance()
{
	if(s_pUniqueInst == NULL)
	{
		//ASSERT(0);
		return NULL;
	}
	return s_pUniqueInst;
}

void TCPProxy::DeleteInstance()
{
	if(s_pUniqueInst != NULL)
	{
		delete s_pUniqueInst ;
		s_pUniqueInst =NULL;
	}
}


int TCPProxy::check_ipversion(char * address)
{
	/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

	struct in6_addr bindaddr;

	if (inet_pton(AF_INET, address, &bindaddr) == 1) {
		return AF_INET;
	} else {
		if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
			return AF_INET6;
		}
	}
	return 0;
}
/* Handle term signal */
void  sigterm_handler(int signal) {
	close( TCPProxy::GetInstance()->m_client_sock);
	close(TCPProxy::GetInstance()->m_server_sock);
	exit(0);
}
/* Create server socket  */
int TCPProxy::create_socket( ) {
	int  optval = 1;
	int validfamily=0;
	struct addrinfo hints, *res=NULL;
	char portstr[12];

	memset(&hints, 0x00, sizeof(hints));
	m_server_sock = -1;

	hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* prepare to bind on specified numeric address */
	if (m_bind_addr != NULL) {
		/* check for numeric IP to specify IPv6 or IPv4 socket */
		if (validfamily = check_ipversion(m_bind_addr)) {
			hints.ai_family = validfamily;
			hints.ai_flags |= AI_NUMERICHOST; /* m_bind_addr is a valid numeric ip, skip resolve */
		}
	} else {
		/* if m_bind_address is NULL, will bind to IPv6 wildcard */
		hints.ai_family = AF_INET6; /* Specify IPv6 socket, also allow ipv4 clients */
		hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
	}

	sprintf(portstr, "%d", m_local_port);

	/* Check if specified socket is valid. Try to resolve address if m_bind_address is a hostname */
	if (getaddrinfo(m_bind_addr, portstr, &hints, &res) != 0) {
		return CLIENT_RESOLVE_ERROR;
	}

	if ((m_server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		return SERVER_SOCKET_ERROR;
	}


	if (setsockopt(m_server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		return SERVER_SETSOCKOPT_ERROR;
	}

	if (bind(m_server_sock, res->ai_addr, res->ai_addrlen) == -1) {
		close(m_server_sock);
		return SERVER_BIND_ERROR;
	}

	if (listen(m_server_sock, BACKLOG) < 0) {
		return SERVER_LISTEN_ERROR;
	}

	if (res != NULL)
		freeaddrinfo(res);

	 signal(SIGTERM,   sigterm_handler); // handle KILL signal

	return m_server_sock;
}



/* Update systemd status with connection count */
void TCPProxy::update_connection_count()
{
#ifdef USE_SYSTEMD
	sd_notifyf(0, "STATUS=Ready. %d connections processed.\n", m_connections_processed);
#endif
}



/* Main server loop */
void TCPProxy::server_loop()
{
	struct sockaddr_storage client_addr;
	socklen_t addrlen = sizeof(client_addr);

#ifdef USE_SYSTEMD
	sd_notify(0, "READY=1\n");
#endif

	while (TRUE)
	{
		update_connection_count();

		m_client_sock = accept(m_server_sock, (struct sockaddr*)&client_addr, &addrlen);
		if (fork() == 0)
		{ // handle client connection in a separate process
			close(m_server_sock);

			handle_client(m_client_sock, client_addr);

			exit(0);
		} else
		{
			m_connections_processed++;
		}


		close(m_client_sock);
	}

}

void TCPProxy::init_ssl()
{
	  /* ---------------------------------------------------------- *
	   * These function calls initialize openssl for correct work.  *
	   * ---------------------------------------------------------- */
	  OpenSSL_add_all_algorithms();
	  ERR_load_BIO_strings();
	  ERR_load_crypto_strings();
	  SSL_load_error_strings();

	  /* ---------------------------------------------------------- *
	   * Create the Input/Output BIO's.                             *
	   * ---------------------------------------------------------- */
	  //certbio = BIO_new(BIO_s_file());
	 // outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

	  /* ---------------------------------------------------------- *
	   * initialize SSL library and register algorithms             *
	   * ---------------------------------------------------------- */
	  if(SSL_library_init() < 0)
	  {
		  //BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
	  }

	  /* ---------------------------------------------------------- *
	   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
	   * ---------------------------------------------------------- */
	  method = SSLv23_client_method();

	  /* ---------------------------------------------------------- *
	   * Try to create a new SSL context                            *
	   * ---------------------------------------------------------- */
	  if ( (ctx = SSL_CTX_new(method)) == NULL)
	  {
		  //BIO_printf(outbio, "Unable to create a new SSL context structure.\n");
	  }

	  /* ---------------------------------------------------------- *
	   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
	   * ---------------------------------------------------------- */
	  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	  /* ---------------------------------------------------------- *
	   * Create new SSL connection state object                     *
	   * ---------------------------------------------------------- */
	  ssl = SSL_new(ctx);
}
void TCPProxy::free_ssl(int server)
{
	  /* ---------------------------------------------------------- *
	   * Free the structures we don't need anymore                  *
	   * -----------------------------------------------------------*/
	  SSL_free(ssl);
	  close(server);
	  //X509_free(cert);
	  SSL_CTX_free(ctx);
	  //BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", (char*)m_remote_url);

}

void TCPProxy::ShowCerts( )
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {

  	    //BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", (char*)m_remote_url);

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
    {
    	//BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", (char*)m_remote_url);
    }
}


/* Handle client connection  CDN or VLC */
void TCPProxy::handle_client(int  client_sock, struct sockaddr_storage client_addr)
{
	m_client_sock2=client_sock;
    //CDN connection
	if ((m_remote_sock = create_connection()) < 0) {
		plog(LOG_ERR, "Cannot connect to host: %m");
		close(m_remote_sock);
		close(m_client_sock2);
		return;
	}

	if(is_remote_ssl())
	{
		init_ssl();
		cout<<"\n** SSL "<<ssl;

		/* ---------------------------------------------------------- *

		 * Attach the SSL session to the socket descriptor            *
		 * ---------------------------------------------------------- */
		SSL_set_fd(ssl, m_remote_sock);
		/* ---------------------------------------------------------- *
		 * Try to SSL-connect here, returns 1 for success             *
		 * ---------------------------------------------------------- */
		if ( SSL_connect(ssl) != 1 )
		{
			//BIO_printf(outbio, "\nError: Could not build a SSL session to: %s.\n",(char*) m_remote_url);
		}
		else
		{
			printf("Successfully enabled SSL/TLS session to");
			//BIO_printf(outbio, "\nSuccessfully enabled SSL/TLS session to: %s.\n", (char*)m_remote_url);
		}

		/* ---------------------------------------------------------- *
		 * Get the remote certificate into the X509 structure         *
		 * ---------------------------------------------------------- */
		//ShowCerts( );
		/* ---------------------------------------------------------- *
		 * extract various certificate information                    *
		 * -----------------------------------------------------------*/
		///certname = X509_NAME_new();
		// certname = X509_get_subject_name(cert);

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

		/* ---------------------------------------------------------- *
		 * display the cert subject here                              *
		 * -----------------------------------------------------------*/
		//BIO_printf(outbio, "Displaying the certificate subject data:\n");
		//X509_NAME_print_ex(outbio, certname, 0, 0);
		//BIO_printf(outbio, "\n");

	}

	if (fork() == 0)
	{ // a process forwarding data from client to remote socket

		forward_data(m_client_sock, m_remote_sock);

		exit(0);
	}

	if (fork() == 0)
	{ // a process forwarding data from remote socket to client

		forward_ext_data(m_remote_sock, m_client_sock);

		exit(0);
	}

}


const char * TCPProxy::get_media_context_type()
{
	string manifest_ext =  ".m3u8";
	string manifest_ext2 =  ".m3u";
	if(m_str_current_http_url.length() >= 4)  {

		if(0 == m_str_current_http_url.compare(m_str_current_http_url.length() - manifest_ext2.length(), manifest_ext2.length(), manifest_ext2))
		{
			return "MANIFEST";

		}

		if(0 == m_str_current_http_url.compare(m_str_current_http_url.length() - manifest_ext.length(), manifest_ext.length(), manifest_ext))
		{

			return "MANIFEST";
		}

		return "SEGMENT";
	}
	return "UNKNOWN";

}



/* Forward data between sockets */
void TCPProxy::forward_data(int source_sock, int destination_sock)
{
	ssize_t bytes;

	char buffer[BUF_SIZE];

	while ((bytes = recv(source_sock, buffer, BUF_SIZE, 0)) > 0)
	{ // read data from client socket

		HTTPProxy httpproxy;

		httpproxy.HTTPForward(buffer,bytes, m_remote_host,m_cdn_url,   m_str_current_http_method,m_str_current_http_url);

		strcpy(current_http_url , m_str_current_http_url.c_str());

		if(0 == strcmp("MANIFEST",get_media_context_type()))
		{
			if(0 != m_str_current_http_url.compare(m_str_current_playlist))
			{
				m_str_current_playlist = m_str_current_http_url;
				cout << "[TRACK SWITCH]\n";
			}

		}

		cout << "[IN]["<< get_media_context_type()<< "] " << (is_ssl? "HTTPS://" : "HTTP://") << string(m_remote_host) << ":" << m_remote_port << m_str_current_http_url <<"\n";
		*m_send_timestamp = GetCurrentTimeMs();

		// send data to output socket
		Send( buffer,bytes,destination_sock );

	}


	if (bytes < 0) {
		plog(LOG_ERR, "read: %m");
		exit(BROKEN_PIPE_ERROR);
	}

	if(is_remote_ssl())
	{
		free_ssl(destination_sock);
	}
	shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
	close(destination_sock);

	shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
	close(source_sock);
}
const char * TCPProxy::media_context_type_to_str() {
	switch( media_context_type) {
	case MANIFEST_TYPE:
		return "MANIFEST";
	case SEGMENT_TYPE:
		return "SEGMENT";
	default:
		return "UNKNOWN";
	}
}
ssize_t TCPProxy::Receive(char*buffer,int source_sock)
{
	ssize_t bytes;
	if(is_remote_ssl())
	{
	   bytes = SSL_read(ssl, buffer, BUF_SIZE); /* get reply & decrypt */
	}
	else
	{
		bytes = recv(source_sock, buffer, BUF_SIZE, 0);
	}
	return bytes;
}

void TCPProxy::Send(char*buffer,int len,int destination_sock )
{
	if(is_remote_ssl())
	{
	    SSL_write(ssl, buffer, len);   /* encrypt & send message */
	}
	else
	{
		send(destination_sock, buffer,len, 0); // send data to output socket
	}

}


/* Forward data between CDN to client  sockets */
void TCPProxy::forward_ext_data(int source_sock, int destination_sock) {
	ssize_t bytes;

	char buffer[ BUF_SIZE];

	while ((bytes =Receive( buffer, source_sock)   ) > 0)
	{ // read data from input socket

		HTTPProxy httpproxy;

		httpproxy.parse_media_context_type(buffer,bytes,media_context_type, m_str_sender_current_http_method,m_str_sender_current_http_url );

        change_url_in_playlist(buffer,bytes,source_sock );

		 // send data to output socket
		send(destination_sock, buffer,bytes, 0); // send data to output socket
		//When the CDN answers and we send back the answer to the player
		double CDN_answer_time = GetCurrentTimeMs();
		//cout << "\n CDN_answer_time "<<CDN_answer_time;
		//cout << "\n m_send_timestamp "<<m_send_timestamp;
		double time_taken    = CDN_answer_time - *m_send_timestamp;

		if(0 !=m_str_last_http_url.compare(current_http_url))
		{

			m_str_last_http_url = string(current_http_url) ;

			cout << "[OUT]["<< media_context_type_to_str()<< "] " << (is_ssl? "https://" : "http://") << string(m_remote_host) << string(current_http_url)<< "(" << time_taken << "ms)\n";
		}
	}


	if (bytes < 0)
	{
		plog(LOG_ERR, "read: %m");
		exit(BROKEN_PIPE_ERROR);
	}

	if(is_remote_ssl())
	{
		free_ssl(source_sock);
	}

	shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
	close(destination_sock);

	shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
	close(source_sock);
}

/* Create client connection */
int TCPProxy::create_connection() {
	struct addrinfo hints, *res=NULL;
	int sock;
	int validfamily=0;
	char portstr[12];

	memset(&hints, 0x00, sizeof(hints));

	// hints.ai_flags    =  //AI_NUMERICSERV; /* numeric service number, not resolve */
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	sprintf(portstr, "%d", m_remote_port);

	/* check for numeric IP to specify IPv6 or IPv4 socket */
	validfamily = check_ipversion(m_remote_url);
	if((AF_INET6 ==validfamily )|| (AF_INET == validfamily))
	{
		hints.ai_family = validfamily;
		hints.ai_flags |= AI_NUMERICHOST;  /* m_remote_url is a valid numeric ip, skip resolve */
	}
	else
	{
		HTTPURL httpurl(m_remote_url);
		m_cdn_url = httpurl.path;

		is_ssl = httpurl.protocol=="https" ? true : false;

		string http_url = m_remote_url;
		m_remote_host = GetDomain( http_url ,m_remote_url);

	}

	/* Check if specified host is valid. Try to resolve address if m_remote_host is a hostname */
	if (getaddrinfo(m_remote_host,portstr , &hints, &res) != 0)
	{
		errno = EFAULT;
		printf("\n CLIENT_RESOLVE_ERROR %s \n ",m_remote_host);
		exit(0);
		return CLIENT_RESOLVE_ERROR;
	}

	if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
	{
		printf("\n CLIENT_SOCKET_ERROR %s \n ",m_remote_url);
		return CLIENT_SOCKET_ERROR;
	}

	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
	{
		printf("\n CLIENT_CONNECT_ERROR %s \n ",m_remote_url);
		return CLIENT_CONNECT_ERROR;
	}

	if (res != NULL)
		freeaddrinfo(res);

	return sock;
}

void TCPProxy::change_url_in_playlist(char buf[],ssize_t&  buflen ,int source_sock)
{

	 std::stringstream data_stream ;
	 std::stringstream output_data_stream;
	std::string str_data_stream =   string(buf );
	std::string line;
	int line_size = 0;
    bool 	is_playlist = false;

    if(
    		( strstr(str_data_stream.c_str(), "#EXTM3U" )) ||
    		( strstr(str_data_stream.c_str(), "#EXTINF:" ))
    )
    {
    	str_data_stream = string(input_playlist_buffer) + string(buf );

    	string remote_host_path = (is_ssl? "https://" : "http://") +string(m_remote_host);
    	replaceAll(str_data_stream, remote_host_path , string(""));


    	data_stream<<str_data_stream;
        strncpy(buf, (char*)str_data_stream.c_str(),BUF_SIZE);
        buf[BUF_SIZE -1 ]= 0;

        buflen = strlen(buf);
    }



}

