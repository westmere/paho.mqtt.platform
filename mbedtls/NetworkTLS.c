/*******************************************************************************
 * Copyright 2017 Andrew Domaszek
 * 
 * All rights reserved.
 * This program made available under BSD-new.
 *******************************************************************************/

/**
 * This example is designed for Linux, using such calls as setsockopt and gettimeofday.
 * On embedded, it's likely that all of the mbedtls_net_* functions would need to be
 * handled by the embedded IP stack and the conn_ctx member would need replacing.
 */
#include "NetworkTLS.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
//#include <sys/socket.h>
#include <mbedtls/error.h>
//#include <sys/time.h>

#define TLS_CA_CERTIFICATE_PATH "/etc/mosquitto/certs/ca.crt"
//#define TLS_NONSTANDARD_SERVER_CN "Example Customer Svr 1 X1"

#if 0
#define tlstrans_LOGERR(...) fprintf(stderr, ## __VA_ARGS__)
#define tlstrans_LOGDEBUG(...) _static_debug_print(stdout, 1, __FILE__, __LINE__, ## __VA_ARGS__)
#define tlstrans_LOG(...) printf(__VA_ARGS__)
#else
#define tlstrans_LOGERR(...) printf(__VA_ARGS__)
#define tlstrans_LOGDEBUG(...) printf(__VA_ARGS__)
#define tlstrans_LOG(...) printf(__VA_ARGS__)
#endif

#define UNUSED_VAR(x) ((void)x)

//#define ENABLE_TIMECHECKING

//static void _static_debug( void *ctx, int level,
//                      const char *file, int line, const char *str )
//{
//  UNUSED_VAR(level);
//  fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
//  fflush(  (FILE *) ctx  );
//}
//
////! @BUG: 1k buff is not small stack friendly.
//static void _static_debug_print( void *ctx, int level, const char * file, int line, const char * format, ... )
//{
//  char buff[1024] = "";
//  char * ostr = buff;
//  va_list args,cnt_args;
//  va_start(args, format);
//  va_copy(cnt_args, args);
//  int cnt = vsnprintf(NULL, 0, format, cnt_args);
//  if (cnt > sizeof(buff)-1) {
//    ostr = (char*)malloc(cnt+1);
//    if (!ostr)
//    {
//      fputs("heap allocation failure in print\n", (FILE *)ctx);
//      abort();
//    }
//  }
//  vsnprintf(ostr, cnt+1, format, args);
//  va_end(args);
//  _static_debug(ctx, level, file, line, ostr);
//  if (ostr != buff)
//    free(ostr);
//}

/* MBEDTLS_DEBUG_C disabled by default to save substantial bloating of
 * firmware, define it in
 * examples/http_get_mbedtls/include/mbedtls/config.h if you'd like
 * debugging output.
 */
#ifdef MBEDTLS_DEBUG_C


/* Increase this value to see more TLS debug details,
   0 prints nothing, 1 will print any errors, 4 will print _everything_
*/
#define DEBUG_LEVEL 4

static void _static_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    /* Shorten 'file' from the whole file path to just the filename

       This is a bit wasteful because the macros are compiled in with
       the full _FILE_ path in each case, so the firmware is bloated out
       by a few kb. But there's not a lot we can do about it...
    */
    char *file_sep = rindex(file, '/');
    if(file_sep)
        file = file_sep+1;

    printf("%s:%04d: %s", file, line, str);
}
#endif

void mbedtls_init(NetworkTLS *tls, const char *cert)
//  read_timeout_ms(400)
{
	int ret;

	mbedtls_net_init(&tls->ctx);
	mbedtls_ssl_init(&tls->ssl);
	mbedtls_ssl_config_init(&tls->conf);
	mbedtls_x509_crt_init(&tls->cacert);
	mbedtls_ctr_drbg_init(&tls->ctr_drbg);
	mbedtls_entropy_init(&tls->entropy);

#ifdef MBEDTLS_FS_IO
	mbedtls_x509_crt_parse_file( &tls->cacert, TLS_CA_CERTIFICATE_PATH ); //! @BUG: Remove hardcoded path
#else
	printf("  . Loading the CA root certificate ...");

	ret = mbedtls_x509_crt_parse(&tls->cacert, (uint8_t*) cert, strlen(cert) + 1);
	if (ret < 0) {
		printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		abort();
	}

	printf(" ok (%d skipped)\n", ret);
#endif
}

void mbedtls_deinit(NetworkTLS *tls)
{
	mbedtls_x509_crt_free(&tls->cacert);
	mbedtls_ssl_free(&tls->ssl);
	mbedtls_ssl_config_free(&tls->conf);
	mbedtls_ctr_drbg_free(&tls->ctr_drbg);
	mbedtls_entropy_free(&tls->entropy);
}

//int mbedtls_tlsFetchData(Network *n, void * self, unsigned char * out, int bytesMax)
//{
//  int rc = n->ctx.read(out, bytesMax, n->ctx.read_timeout_ms);
//
//  if (rc == -1)
//  {
//    // need to check something here to make sure it's not a terminal TLS error.
//  }
//
//  return rc;
//}

int mbedtls_connect(Network *n, const char * hostname, int port)
{
	NetworkTLS *tls = (NetworkTLS *) n->arg;
	assert(port > 0 && port < USHRT_MAX);
	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%d", port); //! @TODO: itoa() instead?
	const char * FUNC_NAME = "";

	int rc = -1;

	// Can provide personalization identifier in arg 4 & 5 for more entropy.
	FUNC_NAME = "mbedtls_ctr_drbg_seed";
	if ((rc = mbedtls_ctr_drbg_seed(&tls->ctr_drbg, mbedtls_entropy_func,
			&tls->entropy, (const unsigned char *) NULL, 0)) != 0)
		goto error_out;

	/*
	 * Start the connection
	 */
	tlstrans_LOG("\n  - Connecting to tcp/%s/%s...", hostname, port_str);
	fflush( stdout);

	FUNC_NAME = "mbedtls_net_connect";
	if ((rc = mbedtls_net_connect(&tls->ctx, hostname, port_str,
			MBEDTLS_NET_PROTO_TCP)) != 0)
		goto error_out;
	tlstrans_LOG(" ok\n");

	FUNC_NAME = "mbedtls_ssl_config_defaults";
	if ((rc = mbedtls_ssl_config_defaults(&tls->conf,
											MBEDTLS_SSL_IS_CLIENT,
											MBEDTLS_SSL_TRANSPORT_STREAM,
											MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		goto error_out;
	}

//  mbedtls_ssl_conf_authmode( &tls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL ); //! @BUG: NO SECURITY.
	mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE); // The authentication mode determines how strict the certificates that are presented are checked.
//	mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL); // should only be set if VERIFY OPTIONAL or REQUIRED.

	mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg);

#ifdef MBEDTLS_DEBUG_C
	mbedtls_ssl_conf_dbg( &tls->conf, _static_debug, stdout ); // debug callback defined above.
#endif

	FUNC_NAME = "mbedtls_ssl_setup";
	if ((rc = mbedtls_ssl_setup(&tls->ssl, &tls->conf)) != 0)
		goto error_out;

	FUNC_NAME = "mbedtls_ssl_set_hostname";
#if defined(TLS_NONSTANDARD_SERVER_CN)
	if( ( rc = mbedtls_ssl_set_hostname( &tls->ssl, TLS_NONSTANDARD_SERVER_CN ) ) != 0 ) //! @BUG: hardcoded CN
	goto error_out;
#else
	if ((rc = mbedtls_ssl_set_hostname(&tls->ssl, hostname)) != 0) //! @TODO: Verify this is necessary and not default behavior.
		goto error_out;
#endif

	mbedtls_ssl_set_bio(&tls->ssl, &tls->ctx, mbedtls_net_send,
			mbedtls_net_recv, NULL);

	/*
	 * 4. TLS Handshake and verification
	 */
	tlstrans_LOG("  - Performing the SSL/TLS handshake...");
	fflush(stdout);
	FUNC_NAME = "mbedtls_ssl_handshake";
	while ((rc = mbedtls_ssl_handshake(&tls->ssl)) != 0) {
		if (rc != MBEDTLS_ERR_SSL_WANT_READ & rc != MBEDTLS_ERR_SSL_WANT_WRITE)
			goto error_out;
	}

	tlstrans_LOG(" success (%d).\n", rc);

	rc = mbedtls_ssl_get_verify_result(&tls->ssl); //! @BUG: if this is non-zero, it should abort. Maybe instead use VERIFY_REQUIRED?
	tlstrans_LOG("CN verify result: %d\n", rc);

	return 0;
error_out:
	tlstrans_LOGERR(" failed\n  ! %s returned %d\n", FUNC_NAME, rc);
	return rc;
}

void mbedtls_disconnect(Network *n)
{
    NetworkTLS *tls = (NetworkTLS *)n->arg;
  mbedtls_net_free(&tls->ctx);
}

int mbedtls_read(Network *n, unsigned char *buffer, int len, int timeout_ms)
{
	NetworkTLS *tls = (NetworkTLS *) n->arg;
//	struct timeval tv;
//	tv.tv_sec = timeout_ms / 1000;
//	tv.tv_usec = (timeout_ms % 1000) * 1000;
//	assert(tv.tv_sec >= 0 && tv.tv_usec >= 0);
//
//#if defined(ENABLE_TIMECHECKING)
//	struct timeval tv1,tv2;
//	gettimeofday(&tv1,NULL);
//#endif
//
//	setsockopt(tls->ctx.fd, SOL_SOCKET, SO_RCVTIMEO, (char * )&tv, sizeof(struct timeval));

	//tlstrans_LOGDEBUG ("Reading %d bytes into %p in %d ms\n", len, buffer, timeout_ms);
	int bytes = 0;
	while (bytes < len) {
#if 1
		//int rc = recv(n->my_socket, &buffer[bytes], (size_t)(len - bytes), 0);
		int rc = mbedtls_ssl_read( &tls->ssl, &buffer[bytes], (size_t)(len - bytes) );
		if (rc <= -1)
		{
			char errbuf[256];
			if (rc == -0x4c) { // seems to be what mbedtls_ssl_read provides when not expecting to timeout...
				bytes = 0;
				break;
			}
			// Otherwise, let's print an error.
			mbedtls_strerror(rc, errbuf, sizeof(errbuf));
			tlstrans_LOGERR("mbedtls_ssl_read returned error -0x%x: %.*s\n", -rc, sizeof(errbuf), errbuf);
			// any error from mbedtls_ssl_read is terminal and the connection must be closed.
			//if (errno != ENOTCONN && errno != ECONNRESET)
			//{
			bytes = -1;
			break;
			//}
		}
		else if (rc == 0)
		{
			bytes = 0;
			break;
		}
		else
		bytes += rc;
#else
		int rc = mbedtls_ssl_read(&tls->ssl, &buffer[bytes], (size_t) (len - bytes));

		if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;

		if (rc == -0x4c)
		{
			// seems to be what mbedtls_ssl_read provides when not expecting to timeout...
			tlstrans_LOGERR("mbedtls_ssl_read returned: -0x%04x: %s\r\n", -rc, strerror(-rc));
			bytes = 0;
			break;
		}

		if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		{
			bytes = 0;
			break;
		}

		if (rc < 0)
		{
			tlstrans_LOGERR("failed\n  ! mbedtls_ssl_read returned -0x%04x\n\n", -rc);
			break;
		}

		if (rc == 0)
		{
			tlstrans_LOGERR("\n\nEOF\n\n");
			break;
		}

		bytes += rc;
#endif
	}

#if defined(ENABLE_TIMECHECKING)
	gettimeofday(&tv2,NULL);
	float sec = ((tv2.tv_sec - tv1.tv_sec) * 1000.0 + (tv2.tv_usec - tv1.tv_usec) / 1000) / 1000;
	//tlstrans_LOG ("...got %d in %.3f sec\n", bytes, sec);
	assert(!(bytes == 0 && sec < 0.001));// This is a weird error with PINGRESP calling a 0-byte read.
#endif

	return bytes;
}

int mbedtls_write(Network *n, unsigned char *buffer, int len, int timeout_ms)
{
	NetworkTLS *tls = (NetworkTLS *) n->arg;
//	struct timeval tv;
//	tv.tv_sec = timeout_ms / 1000;
//	tv.tv_usec = (timeout_ms % 1000) * 1000;
//	assert(tv.tv_sec >= 0 && tv.tv_usec >= 0);
//
//	setsockopt(tls->ctx.fd, SOL_SOCKET, SO_SNDTIMEO, (char * )&tv, sizeof(struct timeval));

	if (timeout_ms == 0) {
		// if timeout_ms == 0, must handle partial writes on our own.
		// ref: https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
		int rc = 0;
		while ((rc = mbedtls_ssl_write(&tls->ssl, buffer, len)) >= 0) {
			assert(rc <= len); // can this be greater than? what does that mean?
			if (rc >= len)
				break;
			buffer += rc;
			len -= rc;
		}
		if (rc < 0)
			return rc;
		return len;
	} else {
		return mbedtls_ssl_write(&tls->ssl, buffer, len);
	}
}

void NetworkTLSInit(Network* n, NetworkTLS *tls, const char *cert)
{
    mbedtls_init(tls, cert);
	n->arg = tls;
	n->mqttread = mbedtls_read;
	n->mqttwrite = mbedtls_write;
	n->connect = mbedtls_connect;
	n->disconnect = mbedtls_disconnect;
//	n->isconnected = nw_lwip_isconnected;
}
