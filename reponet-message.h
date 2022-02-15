/*
 * =====================================================================================
 *
 *       Filename:  reponet-message.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef __REPONET_MESSAGE_H_
#define __REPONET_MESSAGE_H_    1

/* Message containing captured packet */
struct reponet_message {
    size_t  len;            /*  Length of message */
    char    *pktmsg;        /*  Message data: JSON */
    /*  TO-DO
     *  needs to be queue entry */
};

#endif  /*  __REPONET_MESSAGE_H_ */
