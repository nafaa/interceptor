# HLS interceptor

 Interceptor is a simple HLS proxy which intercepts and forwards packets between the HLS player and the CDN by processing HTTP packets.
The Interceptor can be used to easily:
  
  - local HLS proxy streaming 
  - inspect playlist and media context type 
  - debugging the connections between the player and the CDN
  
Code implemented in C/C++.
It's far from being the final version.


Compatibility
===================
  - Only for Linux GNU Compiler  linux 

  - supports HTTPS connections using the OpenSSL transport layer security (TLS) library.
 

Install dependencies
===================
sudo apt-get install -y libssl-dev

Install
===================
Download or clone latest files:
https://github.com/nafaa/interceptor.git

cd interceptor


 Build command: 
===================
    make 


 Usage
===================
  interceptor -b bind_address -l local_port -h remote_hls_url -p remote_port 

  - bind_address : the interceptor bind address
  - local_port :  port to listen 
  - remote_hls_url : full hls URL
  - remote_port : port 80 for http and 443 for https 
 

 Run 
===================
 ./interceptor -b 127.0.0.1 -l 8080 -p 443 -h https://bitdash-a.akamaihd.net/content/MI201109210084_1/m3u8s/f08e80da-bf1d-4e3d-8899-f0f6155f6efa.m3u8 -f



- The anatomy of a full HLS url   = http://remote_host/remote_path
- The URL on your player should be :  http://bind_address:local_port/remote_path

- If we assume server is serving on 127.0.0.1:8080 for the below url put the corresponding url on VLC


	https://bitdash-a.akamaihd.net/content/MI201109210084_1/m3u8s/f08e80da-bf1d-4e3d-8899-f0f6155f6efa.m3u8 

	===>

	http://127.0.0.1:8080/content/MI201109210084_1/m3u8s/f08e80da-bf1d-4e3d-8899-f0f6155f6efa.m3u8


Todo
===================
  - Support for Windows 
  - Creating a logging system to control of log levels and log types
  
License
----

 
 
