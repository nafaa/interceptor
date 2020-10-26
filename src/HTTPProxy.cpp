/*
 * HTTPProxy.cpp
 *
 *  Created on: 25 oct. 2020
 *      Author: Nafaa Zayen
 */

#include "HTTPProxy.h"

HTTPProxy::HTTPProxy() {
	// TODO Auto-generated constructor stub

}

HTTPProxy::~HTTPProxy() {
	// TODO Auto-generated destructor stub
}
//modify HTTP lines and headers.
void HTTPProxy::HTTPForward(char buf[],ssize_t&  buflen,string m_remote_host,string m_cdn_url, string& method, string& url)
{

	HTTPParse( buf ,  buflen, method,   url);

	char * temp = NULL;

	if(0 == method.compare("GET" ))
	{
		if(1 == url.length())
		{
			 url = m_cdn_url;
		}

		string request = string("GET") + string(" ") +
				url +  " HTTP/1.1"+ HTTP_NEWLINE +"Host: " +
				 m_remote_host + HTTP_NEWLINE
				"Accept: */*" HTTP_NEWLINE +  "User-Agent: VLC/3.0.8 LibVLC/3.0.8"  HTTP_NEWLINE
				"Range: bytes=0-" HTTP_NEWLINE HTTP_NEWLINE;
		strcpy(buf, (char*)request.c_str());

		buflen = request.length();

	}

}

void HTTPProxy::parse_media_context_type(char buf[],ssize_t&  buflen, MEDIA_CONTEXT_TYPE&  media_context_type,   string& str_method, string& str_url)
{

	char  *method, *path;
	int pret, minor_version;
	struct phr_header headers[100];
	size_t prevbuflen = 0, method_len, path_len, num_headers;

	if(
			( strstr(buf, "application/vnd.apple.mpegurl")) ||
			( strstr(buf, "audio/mpegurl")) ||
			( strstr(buf, "application/mpegurl")) ||
			( strstr(buf, "application/x-mpegurl")) ||
			( strstr(buf, "audio/x-mpegurl"))
	)
	{

		media_context_type = MANIFEST_TYPE;
	}
	else
	{
		media_context_type = SEGMENT_TYPE;
	}
	return;

}
void HTTPProxy::HTTPParse(char buf[],ssize_t&  buflen,string& str_method, string& str_url)
{
	char  *method, *path;
	int pret, minor_version;
	struct phr_header headers[100];
	size_t prevbuflen = 0, method_len, path_len, num_headers;

	prevbuflen = 0;

	/* parse the request */
	num_headers = sizeof(headers) / sizeof(headers[0]);
	pret = phr_parse_request((const char *)buf, buflen,(const char **) &method, &method_len,(const char **) &path, &path_len,
			&minor_version, headers, &num_headers, prevbuflen);

	//copy cdn path from http header
	char* pos = (char*)memchr( path, '\0',  path_len);
	str_url.assign(path, pos ? pos - path :  path_len);

	 pos = (char*)memchr( method, '\0',  method_len);
	str_method.assign( method, pos ? pos - path :  method_len);



}
