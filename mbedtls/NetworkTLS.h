/*******************************************************************************
 * Copyright 2017 Andrew Domaszek
 * 
 * All rights reserved.
 * This program made available under BSD-new.
 *******************************************************************************/

#pragma once
#ifndef __MQTTTRANSPORT_MBEDTLS_H_
#define __MQTTTRANSPORT_MBEDTLS_H_
#include "Network.h"

/* mbedtls/config.h MUST appear before all other mbedtls headers, or
   you'll get the default config.

   (Although mostly that isn't a big problem, you just might get
   errors at link time if functions don't exist.) */
#include "mbedtls/config.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

typedef struct NetworkTLS NetworkTLS;

struct NetworkTLS
{
	int read_timeout_ms;

	mbedtls_net_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
};

//class MQTTTransport_mbedTLS : public MQTTTransport
//{
//public:
//  explicit MQTTTransport_mbedTLS();
//  VIRTUAL_FCN ~MQTTTransport_mbedTLS();
//
//  /* aed.20170531:
//   *   I disabled copy construction because I don't know if it is safe for
//   *   mbedtls contexts. */
//  MQTTTransport_mbedTLS( const MQTTTransport_mbedTLS& other ) = delete; // non construction-copyable
//  MQTTTransport_mbedTLS& operator=( const MQTTTransport_mbedTLS& ) = delete; // non copyable
//
//  typedef unsigned char tlsDataType;
//
//  static int tlsFetchData(void *, tlsDataType *, int); /* must return -1 for error, 0 for call again, or the number of bytes read */
//
//  VIRTUAL_FCN int connect(const char * hostname, int port);
//  VIRTUAL_FCN int disconnect();
//
//  VIRTUAL_FCN int read(tlsDataType * buffer, int len, int timeout_ms = 0);
//  VIRTUAL_FCN int write(tlsDataType * buffer, int len, int timeout_ms = 0);
//
//  VIRTUAL_FCN int pollableFd() { return conn_ctx.fd; }
//
//protected:
//  int read_timeout_ms;
//
///* mbedtls connection information */
//  mbedtls_net_context conn_ctx;
//  mbedtls_entropy_context entropy;
//  mbedtls_ctr_drbg_context ctr_drbg;
//  mbedtls_ssl_context ssl;
//  mbedtls_ssl_config conf;
//  mbedtls_x509_crt cacert;
//};

void NetworkTLSInit(Network* n, NetworkTLS *tls, const char *cert);

#endif
