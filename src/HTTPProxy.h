/*
 * HTTPProxy.h
 *
 *  Created on: 21 oct. 2020
 *      Author: nafaa
 */

#ifndef HTTPPROXY_H_
#define HTTPPROXY_H_

#include "utility.h"
#include <iostream>
using namespace std;
#include "picohttpparser.h"

#define HTTP_NEWLINE "\r\n"
#define HTTP_SPACE " "
#define HTTP_HEADER_SEPARATOR ": "
enum  MEDIA_CONTEXT_TYPE
{
	 SEGMENT_TYPE = 0,
	 MANIFEST_TYPE
};





class HTTPProxy {
public:
	HTTPProxy();
	void  HTTPParse(char buf[],ssize_t&  buflen,string& str_method, string& str_url);

	void HTTPForward(char buf[],ssize_t&  buflen,string m_remote_host,string m_cdn_url,string& method, string& url);
	void  parse_media_context_type(char buf[],ssize_t&  buflen, MEDIA_CONTEXT_TYPE&  media_context_type,   string& str_method, string& str_url);

	virtual ~HTTPProxy();
};

#endif /* HTTPPROXY_H_ */
