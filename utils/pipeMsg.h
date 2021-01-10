#pragma once

#define PIPE_NAME L"\\\\.\\pipe\\myPipe"

#define REQUEST_MSG 4

#define MSGBOX 1
#define IATHOOK_GCD 2
#define UNIATHOOK 3
#define INLINEHOOK_CREATEPROCESS 4
#define UNINLIEHOOK 5
#define DISCONNECT 6

#define PIPEWAITTIMOUTIFBUSY 20000

#define BUFSIZE 100 // * sizeof(char)
#define MAXPIPEFILESIZE 1024 // Should be the size of the biggest possible request (WPM request, 928 bits)
// At init() I could calculate the sizeof() all the requests and responses struct and use the largest as maxpipefilesize


//typedef ReponseIAT ResponseInline;
//typedef ReponseIAT ReponseIAT;
struct ResponseIAT
{
	int status;
	int* args;
};
