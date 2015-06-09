#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rtthreads.h>
#include <RttCommon.h>
#include <RttThreadId.h>
#include "list.h"

/* network includes */
#include <netinet/in.h>
#include <sys/types.h>

#include <netdb.h>

/* globals */
RttThreadId SERVER_THREAD;
RttThreadId RECEIVE_THREAD;
RttThreadId OUTPUT_THREAD;
RttThreadId INPUT_THREAD;
RttThreadId SEND_THREAD;

struct hostent* THEIR_HSTNM;
struct hostent* MY_HSTNM;

char* CMDLN_THEIRHSTNM;
int CMDLN_MYPORT;
int CMDLN_THEIRPORT;

LIST* outgoing;
LIST* incomming;
  
/* message codes */
#define SERVER 5
#define KEYBOARD 2
#define OUTPUT 3
#define SENDMSG 4
#define RECMSG 1

/* max msg size and expected number of args */
#define MAX_SIZE 32
#define MAX_ARGS 4

#define THREAD_SLEEP 100

/* msg structure for thread communitcation */
typedef struct {
  int msgcode;
  char msg[MAX_SIZE];
  
}threadMessage;


/* thread for sending a message */
RTTTHREAD sendMsg(void * socket){

  
  int* temp;
  int sockfd, rlen, slen;
  char* msg;
  struct sockaddr_in to_comp;
  socklen_t tocomp_len;
  threadMessage s_message, s_reply;
  
  
  /* map socket to local variable */
  temp = (int*) socket;
  sockfd = *temp;

  s_message.msgcode = SENDMSG;

  msg = malloc(sizeof(MAX_SIZE));
  slen = sizeof(threadMessage);


  /* look up hostname */
  THEIR_HSTNM = gethostbyname(CMDLN_THEIRHSTNM);
  if ( THEIR_HSTNM == NULL )
    printf("error with lookup");
  
  /* set other address */
  to_comp.sin_family = AF_INET;
  to_comp.sin_addr = *(struct in_addr *) THEIR_HSTNM->h_addr;
  to_comp.sin_port = htons (CMDLN_THEIRPORT);
  
  /* set sin_zero and buf to zero */
  memset(to_comp.sin_zero, '\0', sizeof to_comp.sin_zero);
  
  tocomp_len = sizeof(struct sockaddr_in);
  
  while ( 1 ) {
    /*RttSend checks message */
    if ( RttSend(SERVER_THREAD,(void *) &s_message,(u_int) slen, (void*) &s_reply ,(u_int*) &rlen) == RTTOK )  {
	
	  if ( strcmp(s_reply.msg, "\0") != 0 ) {
	    strcpy(msg, s_reply.msg);
	    RttSendto(sockfd, msg, MAX_SIZE, 0,(struct sockaddr *)&to_comp, tocomp_len);
	    memset(s_reply.msg, '\0', sizeof(s_reply.msg));
	  } 
    }
     RttUSleep(THREAD_SLEEP);
    
  }
  close(sockfd);
}

/* Receive message over the network and send
 it to the server thread */
RTTTHREAD receiveMsg(void * socket){
  
  char* tempHostName;
  int* temp;
  int sockfd, slen, rlen;
  threadMessage r_message, r_reply;
  socklen_t serverlen, senderlen;
  struct sockaddr_in server, sender;
  

  /* map socket to local variable */
  temp = (int*) socket;
  sockfd = *temp;
  
  /* malloc required space */
  tempHostName = malloc(sizeof(MAX_SIZE));
  
  r_message.msgcode = RECMSG;

  slen = sizeof(threadMessage);
 
  /* check hostname is legitimate */
  gethostname(tempHostName, MAX_SIZE);
  MY_HSTNM = gethostbyname(tempHostName);
   if ( MY_HSTNM == NULL )
    printf("error with hostname lookup");

  /* set server structure up */
  server.sin_family = AF_INET;
  server.sin_addr = *(struct in_addr *) MY_HSTNM->h_addr;
  server.sin_port = htons(CMDLN_MYPORT);
  
  /* set sin_zero and buf to zero */
  memset(server.sin_zero, '\0', sizeof server.sin_zero);

  
  /* set size of server and sender to sockaddr */
  senderlen = sizeof(struct sockaddr_in);
  serverlen = sizeof(struct sockaddr_in);
  
  if ( (RttBind(sockfd, (struct sockaddr*) &server, serverlen) ) < 0 )
    printf("error binding RECIEVE\n");
  

  /* wait for message */
  while ( 1 ) {
    
    RttRecvfrom(sockfd, r_message.msg, MAX_SIZE, 0 , (struct sockaddr*)&sender, (int*) &senderlen);
	  
      if ( ( RttSend(SERVER_THREAD, (void*) &r_message, (u_int) slen, (void*) &r_reply, (u_int *) &rlen) ) == RTTOK ) {
	/* zero out buffer if msg was sent successfully */
	memset(r_message.msg, '\0', sizeof(r_message.msg));
   
    }
    RttUSleep(THREAD_SLEEP);
  }
    
  close(sockfd);
}

/* thread for displaying a message to screen */
RTTTHREAD outputMsg(){
 
  int slen, rlen;
  threadMessage op_message, op_reply;

  op_message.msgcode = OUTPUT;
  slen = sizeof(threadMessage);
  
  
  while ( 1 ) {

    if ( ( RttSend(SERVER_THREAD, (void*)&op_message, (u_int) slen, (void*) &op_reply, (u_int*) &rlen ) ) == RTTOK ) {
	RttWrite(1, op_reply.msg, MAX_SIZE);
	RttUSleep(THREAD_SLEEP);
	memset(op_reply.msg, '\0', sizeof op_reply.msg);
    }
    else
      printf("error with send to server from outputmsg thread");
  }
}

/* thread for typing a message */
RTTTHREAD inputMsg(){
 
  
  int slen, rlen, error;
  threadMessage kb_message, kb_reply;
  
  kb_message.msgcode = KEYBOARD;
  slen = sizeof(threadMessage);
  
  
  while ( 1 ) {
    
    error = RttRead(0, kb_message.msg, MAX_SIZE);
  
    if ( error < 0 )
	printf("error with send");

    if ( ( RttSend(SERVER_THREAD, (void*)&kb_message, (u_int) slen, (void*) &kb_reply, (u_int*) &rlen ) ) == RTTOK ) {
	RttUSleep(THREAD_SLEEP);
	memset(kb_message.msg, '\0', sizeof kb_message.msg);
    }
    else {
      printf("error with send to server from inputMsg thread");
    }
  
  }
}

/* Parent thread that communicates with other threads */
RTTTHREAD server(){

  
  char testMSG[MAX_SIZE];
  char* msgInsert;
  RttThreadId from;
  threadMessage serverTM, localTM;
  int rlen;

  outgoing = ListCreate();
  incomming = ListCreate();
 
  rlen = sizeof(threadMessage);
  
  if (outgoing == NULL || incomming == NULL) {
    printf("error allocating lists for messages");
  }
  
  while( 1 ) {
    
    RttUSleep(THREAD_SLEEP);

    rlen = sizeof(threadMessage);
    /* check if a msg is waiting */
    if (RttMsgWaits()) {
	RttReceive(&from, (void*) &localTM, (u_int *) &rlen);
	
	if ( strcmp(localTM.msg, "q\n") == 0 ) { 
	  RttKill(RECEIVE_THREAD);
	  RttKill(OUTPUT_THREAD);
	  RttKill(INPUT_THREAD);
	  RttKill(SEND_THREAD);
	  RttExit();
	}
	 
	/* check which thread is sending msg and determine what to do */
	switch (localTM.msgcode) {
	  
	  /* rec msg from network */
	  case 1:
	    if ( (RttReply(from, (void*) &serverTM, (u_int) rlen) ) == RTTOK) {
		if (ListCount(incomming) == 0 ) {
		    msgInsert = malloc(sizeof(localTM.msg));
		    memcpy(msgInsert, localTM.msg, sizeof localTM.msg);
		    ListInsert(incomming, msgInsert);
		}
		  else {
		    msgInsert = malloc(sizeof(localTM.msg));
		    memcpy(msgInsert, localTM.msg, sizeof localTM.msg);
		    ListPrepend(incomming, msgInsert);
		    memset(localTM.msg, '\0', sizeof localTM.msg);
		  }
	     }
	      break;
	      
	  /*msg from keyboardinput */
	  case 2:
	    
	    if ( (RttReply(from, (void*) &serverTM, (u_int) rlen) ) == RTTOK) {
		  /* messages are added to the outgoing list */
		  
		  if (ListCount(outgoing) == 0 ) {
		    msgInsert = malloc(sizeof(localTM.msg));
		    memcpy(msgInsert, localTM.msg, sizeof localTM.msg);
		    ListInsert(outgoing, msgInsert);
		   
		  }
		  else {
		    msgInsert = malloc(sizeof(localTM.msg));
		    memcpy(msgInsert, localTM.msg, sizeof localTM.msg);
		    ListPrepend(outgoing, msgInsert);
		  }
		  /*clear msg */
		  memset(localTM.msg, '\0', sizeof localTM.msg);
	    }
	
	    break;
	      
	    /*output to monitor case */
	  case 3:
	      if ( ListCount(incomming) > 0 ) {
		strcpy(testMSG, (char*) ListTrim(incomming));
		strcpy(serverTM.msg, testMSG);
		RttReply(from, (void*) &serverTM, (u_int) rlen);
	      }
	      else {
		memset(serverTM.msg, '\0', sizeof serverTM.msg);
		RttReply(from, (void*) &serverTM, (u_int) rlen);
	      }
	    break;
	    
	    /* send msg over network case */
	  case 4:
	      if ( ListCount(outgoing) > 0 ) { 
	
		  strcpy(testMSG, (char*) ListTrim(outgoing));
		  strcpy(serverTM.msg, testMSG);
		  RttReply(from, (void*) &serverTM, (u_int) rlen); 
	      }
	      else {
		memset(serverTM.msg, '\0', sizeof serverTM.msg);
		RttReply(from, (void*) &serverTM, (u_int) rlen);
	      }
	    break;
	    
	  default:
	    printf("unknown threadid");
	
	}
    
	
    }	
	
	
    }
    
   
}

/* start threads, check input, and socket */
void mainp(int argc, char* argv[]) {

  /* save input as globals to be
   * used in send recieve threads */
 
  RttSchAttr attrs;
  int* sockfd;
  
  sockfd = malloc(sizeof(int));
  if ( argc == MAX_ARGS ){
    if ( !( ( CMDLN_MYPORT = strtod(argv[1], NULL) ) || !( CMDLN_MYPORT > 0 ) ) ||
      ( !( CMDLN_THEIRPORT = strtod(argv[3], NULL) ) || !( CMDLN_MYPORT > 0 ) ) ) {
      printf("error processing input\n");
    }
    else {
    
        /*assign cmdline hostnames for mine and theirs */
	CMDLN_THEIRHSTNM = argv[2];
      
	/* set attributes for threads */
	attrs.startingtime = RTTZEROTIME;
	attrs.priority = RTTHIGH;
	attrs.deadline = RTTNODEADLINE;
	
	*sockfd = RttSocket(PF_INET, SOCK_DGRAM, 0);
	
	RttCreate(&SERVER_THREAD, server, 1600000, "SERVER_THREAD", NULL, attrs, RTTUSR);
	
	RttCreate(&INPUT_THREAD, inputMsg, 1600000, "INPUT_THREAD", NULL, attrs, RTTUSR);
	
	RttCreate(&RECEIVE_THREAD, receiveMsg, 160000, "RECEIVE_THREAD", sockfd, attrs, RTTUSR);
	
	RttCreate(&SEND_THREAD, sendMsg, 160000, "SEND_THREAD",  sockfd, attrs, RTTUSR);
	
	RttCreate(&OUTPUT_THREAD, outputMsg, 160000, "OUTPUT_THREAD", NULL, attrs, RTTUSR);
	
	printf("\n\\/\\/\\/\\/\\/\\/s-chat program started with %s \\/\\/\\/\\/\\/\\/\n type q to quit\n", CMDLN_THEIRHSTNM);


    }
      
  }
  else
    printf("4 command line args needed\n");

}
