/*
 * ssh.c
 *
 * Copyright (C) 2012 Cian Mc Govern <cian@cianmcgovern.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */

#define _GNU_SOURCE

#include <libssh2.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <syslog.h>
#include <string.h>
#include <pthread.h>
#include <gcrypt.h>
#include <errno.h>

#include "remote.h"
#include "ssh.h"
#include "global.h"

/* libgcrypt MACRO to initialise gcrypts pthread functionality */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/* Taken from the libssh2 examples
 * Waits for a max of 10 seconds for a response  */
static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd,&fd);

    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

char** execute_command(struct remote *rm,char commands[][12], int num_commands)
{

    /* Sets up the pthread functionality of gcrypt
     * libssh2 doesn't do this for us so we have to do it ourselves*/
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

    openlog("remote-monitor-base",LOG_PID|LOG_CONS,LOG_USER);

    char *hostname = rm->hostname;
    char *username = rm->username;
    char *password = rm->password;
    int port = rm->port;
    
    syslog(LOG_DEBUG,"Starting SSH execution on hostname: %s with username: %s and port: %d",hostname,username,port);

    size_t len;
    int type;

    unsigned long hostaddress;
    int sock;
    const char *fingerprint;
    int bytecount = 0;

    struct sockaddr_in sin;

    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_KNOWNHOSTS *nh;

    /* results stores the output from the commands after they're executed
     * Each command  has a corresponding result so the results array is set to the same length as the commands array  */
    char **results = malloc(num_commands * sizeof(char*));
    for(int i = 0; i < num_commands; i++)
        results[i] = malloc(2000 * sizeof(char));

    /* Initialise libssh2 and check to see if it was initialized properly
     * libssh2_init isn't thread safe so we need to lock the thread while it executes*/
    pthread_mutex_lock(&sshinit_lock);
    int rc = libssh2_init(0);
    pthread_mutex_unlock(&sshinit_lock);
    if(rc!=0) {
        syslog(LOG_ERR,"libssh2 initilization failed");
        return NULL;
    }

    /* Creates a socket connection to the specified host on the specified port */
    hostaddress = inet_addr(hostname);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = hostaddress;

    /* Check to see if the connection was successful */
    if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        syslog(LOG_ERR,"Failed to connect to %s on port %d", hostname, port);
        return NULL;
    }

    /* Initialise the session and check for success */
    session = libssh2_session_init();
    if(!session) {
        syslog(LOG_ERR,"Error creating session on host %s", hostname);
        return NULL;
    }

    /* Disable blocking for this session */
    libssh2_session_set_blocking(session,0);

    /* Start the session on the specified socket and check for success */
    while( (rc = libssh2_session_startup(session,sock)) == LIBSSH2_ERROR_EAGAIN);
    if(rc) {
        syslog(LOG_ERR,"Failure establishing SSH session %d on host %s", rc, hostname);
        return NULL;
    }

    /* Get the current host key and check to see if it matches with any known hosts */
    nh = libssh2_knownhost_init(session);
    if(!nh) {
        syslog(LOG_ERR,"Error while initialising known hosts collection on host %s",hostname);
        return NULL;
    }
    libssh2_knownhost_readfile(nh,"known_hosts",LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    //libssh2_knownhost_writefile(nh,"dumpfile",LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    fingerprint = libssh2_session_hostkey(session,&len,&type);

    if(fingerprint) {
        struct libssh2_knownhost *host;

        int check = libssh2_knownhost_checkp(nh,hostname,port,fingerprint,len
                ,LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW,&host);

        if(check == LIBSSH2_KNOWNHOST_CHECK_MATCH)
            syslog(LOG_DEBUG,"Found matching host key for host %s",hostname);
        else if(check == LIBSSH2_KNOWNHOST_CHECK_MISMATCH)
            syslog(LOG_ERR,"Host key was found but the key's didn't match for host %s",hostname);
            //TODO Some sort of critical error will need to be generated here
        else if(check == LIBSSH2_KNOWNHOST_CHECK_NOTFOUND)
            syslog(LOG_ERR,"No host match was found for %s",hostname);
            //TODO Have the ability to add the host key here
        else
            syslog(LOG_ERR,"There was a failure while attempting to match host keys for host %s",hostname);
    }
    else {
        syslog(LOG_ERR,"Couldn't get host key for host: %s",hostname);
        return NULL;
    }

    libssh2_knownhost_free(nh);

    /* Authenticate with the specified username and passwod and check for success */
    // TODO Add ability to authenticate with a private key
    while( (rc = libssh2_userauth_password(session,username,password)) == LIBSSH2_ERROR_EAGAIN);
    if(rc) {
        syslog(LOG_ERR,"Authentication to host %s failed",hostname);
        goto shutdown;
    }
    
    /* Open a session for each command */
    for(int i = 0; i < num_commands; i++) {

        /* Open a channel on the current channel and check for success */
        while( (channel = libssh2_channel_open_session(session)) == NULL && libssh2_session_last_error(session,NULL,NULL,0) == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock,session);
        }
        if(channel == NULL) {
            syslog(LOG_ERR,"Error opening SSH channel on host %s",hostname);
            asprintf(&(results[i]),NULL);
            break;
        }

        /* Execute the command and check for success */
        while( (rc = libssh2_channel_exec(channel,commands[i])) == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock,session);
        }
        if(rc!=0) {
            syslog(LOG_ERR,"Error while executing %s in channel on host %s",commands[i],hostname);
            asprintf(&(results[i]),NULL); 
            break;
        }

        /* Continuously read the returned stream and break once the stream has been read */
        for(;;) {
            int rc;
            do
            {
                char buffer[2048];

                rc = libssh2_channel_read(channel,buffer,sizeof(buffer));

                if(rc > 0) {
                    bytecount += rc;
                    char *output;
                    output = buffer;
                    syslog(LOG_ERR,"Got output from command %s on host %s:%s",commands[i],hostname,output);
                    /* Store the output in the results array */
                    asprintf(&(results[i]),"%s",output);
                    memset(buffer,0,2048);
                }
            } while(rc > 0);

            if(rc == LIBSSH2_ERROR_EAGAIN) {
                waitsocket(sock,session);
            }
            else
                break;
        
        }

        /* Close the channel and check for success */
        while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock,session);
        }
        if( (libssh2_channel_free(channel)) < 0)
            syslog(LOG_ERR,"Error while freeing channel on host %s",hostname);
        channel = NULL;
    }

shutdown:

    syslog(LOG_DEBUG,"Disconnecting SSH session for host %s",hostname);

    libssh2_session_disconnect(session,"Normal SSH disconnection");
    libssh2_session_free(session);

    close(sock);

    libssh2_exit();

    closelog();

    return results;
}
