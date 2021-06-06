#pragma warning(disable: 4996)

#pragma comment(lib, "ws2_32.lib")


#include <iostream>
#include <cstdio>
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>

struct ICMPheader
{
	unsigned char	byType;
	unsigned char	byCode;
	unsigned short	nChecksum;
	unsigned short	nId;
	unsigned short	nSequence;
};

struct IPheader
{
	unsigned char	byVerLen;
	unsigned char	byTos;
	unsigned short	nTotalLength;
	unsigned short	nId;
	unsigned short	nOffset;
	unsigned char	byTtl;
	unsigned char	byProtocol;
	unsigned short	nChecksum;
	unsigned int	nSrcAddr;
	unsigned int	nDestAddr;
};

using namespace std;

unsigned short CalcChecksum(char* pBuffer, int nLen);
bool ValidateChecksum(char* pBuffer, int nLen);
bool Initialize();
bool UnInitialize();
bool ResolveIP(char* pszRemoteHost, char** pszIPAddress);
void PrintUsage();



int main(int argc, char* argv[])
{
	WSAData wsaData;
	WORD DLLVersion = MAKEWORD(2, 1);
	if (WSAStartup(DLLVersion, &wsaData) != 0) {
		std::cout << "Error" << std::endl;
		exit(1);
	}
	if (argc < 2 || argc > 6)
	{
		PrintUsage();
		return 0;
	}

	if (Initialize() == false)
	{
		return -1;
	}

	int nSequence = 0;
	int nMessageSize = 32;
	int nTimeOut = 3000;
	int nHopCount = 30;	
	int nMaxRetries = 3;

	char* pszRemoteIP = NULL, * pSendBuffer = NULL, * pszRemoteHost = NULL;

	pszRemoteHost = argv[1];

	for (int i = 2; i < argc; ++i)
	{
		switch (i)
		{
		case 2:
			nHopCount = atoi(argv[2]);
			break;
		case 3:
			nMessageSize = atoi(argv[3]);
			break;
		case 4:
			nMaxRetries = atoi(argv[4]);
			break;
		case 5:
			nTimeOut = atoi(argv[5]);
			break;
		}
	}
	if (ResolveIP(pszRemoteHost, &pszRemoteIP) == false)
	{
		cerr << endl << "Unable to resolve hostname" << endl;
		return -1;
	}

	cout << "Tracing route to " << pszRemoteHost << " [" << pszRemoteIP << "] over a maximum of " << nHopCount
		<< " hops." << endl << endl;
	ICMPheader sendHdr;

	SOCKET sock;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	SOCKADDR_IN destAddr;
	destAddr.sin_addr.S_un.S_addr = inet_addr(pszRemoteIP);
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = rand();	

	SOCKADDR_IN remoteAddr;
	int nRemoteAddrLen = sizeof(remoteAddr);

	int nResult = 0;
	SYSTEMTIME timeSend, timeRecv;

	fd_set fdRead;

	timeval timeInterval = { 0, 0 };
	timeInterval.tv_usec = nTimeOut * 1000;

	sendHdr.nId = htons(rand());
	sendHdr.byCode = 0;	
	sendHdr.byType = 8;	

	int nHopsTraversed = 0;
	int nTTL = 1;

	while (nHopsTraversed < nHopCount && memcmp(&destAddr.sin_addr, &remoteAddr.sin_addr, sizeof(in_addr)) != 0){
		cout << "  " << nHopsTraversed + 1;

		if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char*)&nTTL, sizeof(nTTL)) == SOCKET_ERROR)
		{
			cerr << endl << "An error occured in setsockopt operation: " << "WSAGetLastError () = " << WSAGetLastError() << endl;
			UnInitialize();
			delete[]pSendBuffer;
			return -1;
		}

		pSendBuffer = new char[sizeof(ICMPheader) + nMessageSize];
		sendHdr.nSequence = htons(nSequence++);
		sendHdr.nChecksum = 0;	

		memcpy_s(pSendBuffer, sizeof(ICMPheader), &sendHdr, sizeof(ICMPheader));
		memset(pSendBuffer + sizeof(ICMPheader), 'x', nMessageSize);

		sendHdr.nChecksum = htons(CalcChecksum(pSendBuffer, sizeof(ICMPheader) + nMessageSize));

		memcpy_s(pSendBuffer, sizeof(ICMPheader), &sendHdr, sizeof(ICMPheader));

		
		int nRetries = 0;

		IPheader ipHdr;

		bool bGotAResponse = false;
		while (nRetries < nMaxRetries)
		{
			nResult = sendto(sock, pSendBuffer, sizeof(ICMPheader) + nMessageSize, 0, (SOCKADDR*)&destAddr,
				sizeof(SOCKADDR_IN));

			::GetSystemTime(&timeSend);

			if (nResult == SOCKET_ERROR)
			{
				cerr << endl << "An error occured in sendto operation: " << "WSAGetLastError () = " << WSAGetLastError() << endl;
				UnInitialize();
				delete[]pSendBuffer;
				return -1;
			}

			FD_ZERO(&fdRead);
			FD_SET(sock, &fdRead);

			if ((nResult = select(0, &fdRead, NULL, NULL, &timeInterval)) == SOCKET_ERROR)
			{
				cerr << endl << "An error occured in select operation: " << "WSAGetLastError () = " << WSAGetLastError() << endl;
				delete[]pSendBuffer;
				return -1;
			}

			if (nResult > 0 && FD_ISSET(sock, &fdRead))
			{
				char* pRecvBuffer = new char[1500];

				if ((nResult = recvfrom(sock, pRecvBuffer, 1500, 0, (SOCKADDR*)&remoteAddr, &nRemoteAddrLen))== SOCKET_ERROR)
				{
					cerr << endl << "An error occured in recvfrom operation: " << "WSAGetLastError () = " <<
						WSAGetLastError() << endl;
					UnInitialize();
					delete[]pSendBuffer;
					delete[]pRecvBuffer;
					return -1;
				}

				::GetSystemTime(&timeRecv);

				bGotAResponse = true;

		
				ICMPheader recvHdr;
				char* pICMPbuffer = NULL;

				pICMPbuffer = pRecvBuffer + sizeof(IPheader);

				int nICMPMsgLen = nResult - sizeof(IPheader);

				memcpy_s(&recvHdr, sizeof(recvHdr), pICMPbuffer, sizeof(recvHdr));

				memcpy_s(&ipHdr, sizeof(ipHdr), pRecvBuffer, sizeof(ipHdr));

				recvHdr.nId = recvHdr.nId;
				recvHdr.nSequence = recvHdr.nSequence;
				recvHdr.nChecksum = ntohs(recvHdr.nChecksum);

				if (ValidateChecksum(pICMPbuffer, nICMPMsgLen))
				{
					int nSec = timeRecv.wSecond - timeSend.wSecond;
					if (nSec < 0)
					{
						nSec = nSec + 60;
					}

					int nMilliSec = abs(timeRecv.wMilliseconds - timeSend.wMilliseconds);

					int nRoundTripTime = 0;
					nRoundTripTime = abs(nSec * 1000 - nMilliSec);

					cout << '\t' << nRoundTripTime << " ms";
				}
				else
				{
					cout << "\t!";
				}

				delete[]pRecvBuffer;
			}
			else
			{
				cout << "\t*";
			}
			++nRetries;
		}

		if (bGotAResponse == false)
		{
			cout << "\tRequest timed out.";
		}
		else
		{
			in_addr in;
			in.S_un.S_addr = ipHdr.nSrcAddr;

			char* pszSrcAddr = inet_ntoa(in);
			char szHostName[NI_MAXHOST];

			if (getnameinfo((SOCKADDR*)&remoteAddr,
				sizeof(SOCKADDR_IN),
				szHostName,
				NI_MAXHOST,
				NULL,
				0,
				NI_NUMERICSERV) == SOCKET_ERROR)
			{
				strncpy_s(szHostName, NI_MAXHOST, "Error resolving host name", _TRUNCATE);
			}
			cout << '\t' << szHostName << " [" << pszSrcAddr << "]";
		}

		cout << endl << '\r';
		++nHopsTraversed;
		++nTTL;

		delete[]pSendBuffer;
	}

	if (UnInitialize() == false)
	{
		return -1;
	}

	cout << endl << "Trace complete." << endl;

	return 0;
}

unsigned short CalcChecksum(char* pBuffer, int nLen)
{
	
	unsigned short nWord;
	unsigned int nSum = 0;
	int i;

	for (i = 0; i < nLen; i = i + 2)
	{
		nWord = ((pBuffer[i] << 8) & 0xFF00) + (pBuffer[i + 1] & 0xFF);
		nSum = nSum + (unsigned int)nWord;
	}


	while (nSum >> 16)
	{
		nSum = (nSum & 0xFFFF) + (nSum >> 16);
	}

	nSum = ~nSum;

	return ((unsigned short)nSum);
}

bool ValidateChecksum(char* pBuffer, int nLen)
{
	unsigned short nWord;
	unsigned int nSum = 0;
	int i;

	for (i = 0; i < nLen; i = i + 2)
	{
		nWord = ((pBuffer[i] << 8) & 0xFF00) + (pBuffer[i + 1] & 0xFF);
		nSum = nSum + (unsigned int)nWord;
	}


	while (nSum >> 16)
	{
		nSum = (nSum & 0xFFFF) + (nSum >> 16);
	}
	
	return ((unsigned short)nSum == 0xFFFF);
}

bool Initialize()
{
	
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == SOCKET_ERROR)
	{
		cerr << endl << "An error occured in WSAStartup operation: " << "WSAGetLastError () = " << WSAGetLastError() << endl;
		return false;
	}

	SYSTEMTIME time;
	::GetSystemTime(&time);


	srand(time.wMilliseconds);

	return true;
}

bool UnInitialize()
{

	if (WSACleanup() == SOCKET_ERROR)
	{
		cerr << endl << "An error occured in WSACleanup operation: WSAGetLastError () = " << WSAGetLastError() << endl;
		return false;
	}

	return true;
}

bool ResolveIP(char* pszRemoteHost, char** pszIPAddress)
{
	hostent* pHostent = gethostbyname(pszRemoteHost);
	if (pHostent == NULL)
	{
		cerr << endl << "An error occured in gethostbyname operation: WSAGetLastError () = " << WSAGetLastError() << endl;
		return false;
	}

	in_addr in;
	memcpy_s(&in, sizeof(in_addr), pHostent->h_addr_list[0], sizeof(in_addr));
	*pszIPAddress = inet_ntoa(in);

	return true;
}

void PrintUsage()
{
	cout << "Usage: tracert r h b n t" << endl << endl;
	cout << "  r - Remote host" << endl;
	cout << "  h - Maximum number of hops" << endl;
	cout << "  b - Bytes to send" << endl;
	cout << "  n - Number of requests to send" << endl;
	cout << "  t - Timeout after these many milliseconds" << endl << endl;

	cout << "\rtracert microsoft.com 30 32 3 3000" << endl << endl;
}