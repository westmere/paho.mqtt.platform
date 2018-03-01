/*******************************************************************************
 * Copyright (c) 2014, 2015 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *******************************************************************************/

#if !defined(MQTT_NETWORK_H)
#define MQTT_NETWORK_H

typedef struct Network Network;

struct Network
{
	void *arg;
	int (*mqttread) (Network *, unsigned char *, int, int);
	int (*mqttwrite) (Network *, unsigned char *, int, int);
    int (*connect) (Network *, const char *, int);
	void (*disconnect) (Network *);
	int (*isconnected) (Network *);
};

void NetworkInit(Network *,void *);
int NetworkConnect(Network *, char *, int);
/*int NetworkConnectTLS(Network*, char*, int, SlSockSecureFiles_t*, unsigned char, unsigned int, char);*/

#endif
