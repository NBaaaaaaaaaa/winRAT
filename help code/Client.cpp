#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")


typedef struct {
	DWORD s_un;
} in_addr_custom;

typedef struct {
	WORD sin_family;
	WORD sin_port;
	in_addr_custom sin_addr;
	BYTE sin_zero[8];
} sockaddr_in_custom;

typedef struct {
	WORD wVersion;
	WORD wHighVersion;
	BYTE szDescription[257];
	BYTE szSystemStatus[129];
	WORD iMaxSockets;
	WORD iMaxUdpDg;
	DWORD lpVendorInfo;
} WSADATA_custom;

void closeAll(SOCKET* ClientSocket) {

	if (ClientSocket != NULL) {
		if (closesocket(*ClientSocket) == SOCKET_ERROR) {
			printf("  [-] ������ � closesocket(): %d\n", WSAGetLastError());
		}
		printf("  [+] ����� � closesocket() (client)\n");
	}

	if (WSACleanup() == SOCKET_ERROR) {
		printf("  [-] ������ � WSACleanup(): %d\n", WSAGetLastError());
	}
	printf("  [+] ����� � WSACleanup()\n");

	return;
}

SOCKET ClientSocket;
FILE* file;
char fileName[] = "funcInfo";
int packet_size;


void send_file() {
	char buf[512];
	char endSignal = 0x01;
	Sleep(200);

	if (fopen_s(&file, fileName, "rb") != 0 || !file) {
		packet_size = send(ClientSocket, &endSignal, 1, 0);	// ���������� ��������� ����
		return;
	}

	// ������ � �������� ������
	size_t bytesRead;
	while ((bytesRead = fread(buf, 1, 512, file)) > 0) {
		if (send(ClientSocket, buf, bytesRead, 0) == SOCKET_ERROR) {
			perror("Send failed");
			closeAll(&ClientSocket);
		}
		printf("a");
		Sleep(1500);
	}

	if (send(ClientSocket, &endSignal, 1, 0) == SOCKET_ERROR) { // ���������� ��������� ����
		perror("Failed to send end signal");
	}
	printf("b");
	fclose(file);
	return;
}

int main() {
	WSADATA wsadata;
	sockaddr_in_custom saClient;
	struct in_addr ip_to_num;

	char* locale = setlocale(LC_ALL, "");

	printf("[=] ������ �������\n");

	// ���� ������������� �������� �����������
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		printf("  [-] ������ � WSAStartup(): %d\n", WSAGetLastError());
		return 1;
	}
	//printf("  [+] ����� � WSAStartup()\n");

	// ���� �������� ������ � ��� �������������
	ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (ClientSocket == INVALID_SOCKET) {
		printf("  [-] ������ � socket(): %d\n", WSAGetLastError());
		closeAll(&ClientSocket);

		return  1;
	}
	//printf("  [+] ����� � socket()\n");

	ZeroMemory(&saClient, sizeof(saClient));
	saClient.sin_family = AF_INET;
	saClient.sin_addr.s_un = 0x819da8c0; //'192.168.157.129'
	saClient.sin_port = 0x07d0;	//2000

	if (connect(ClientSocket, (struct sockaddr*)&saClient, sizeof(saClient)) == SOCKET_ERROR) {
		printf("  [-] ������ � connect(): %d\n", WSAGetLastError());
		closeAll(&ClientSocket);

		return 1;
	}
	//printf("  [+] ����� � connect()\n");

	char buf[512];

	while (1) {
		// ��������� ����������� 
		ZeroMemory(&buf, sizeof(buf));
		packet_size = recv(ClientSocket, buf, 512, 0);

		if (packet_size == SOCKET_ERROR) {
			printf("    [-] ������ � recv(): %d\n", WSAGetLastError());
			closeAll(&ClientSocket);
			return 1;
		}

		printf("%s", buf);

		// �������� �������
		ZeroMemory(&buf, sizeof(buf));
		if (fgets(buf, sizeof(buf), stdin) != NULL) {
			// ������� ������ ����� ������, ���� �� ������������
			size_t len = strlen(buf);
			if (len > 0 && buf[len - 1] == '\n') {
				buf[len - 1] = '\0';
			}

			packet_size = send(ClientSocket, buf, (int)len, 0);

			if (packet_size == SOCKET_ERROR) {
				printf("    [-] ������ � send(): %d\n", WSAGetLastError());
				closeAll(&ClientSocket);
				return 1;
			}

			// ���� ���������� �������
			if (strncmp(buf, "addFunc", strlen("addFunc")) == 0) {
				send_file();
			}
			// ���� �������� �������
			else if (strncmp(buf, "delFunc", strlen("delFunc")) == 0) {
				send_file();
			}

		}
		else {
			printf("������ ������ ������\n");
			closeAll(&ClientSocket);
			return 1;	
		}
			

		// ��������� ���������� �������
		ZeroMemory(&buf, sizeof(buf));
		packet_size = recv(ClientSocket, buf, 512, 0);

		if (packet_size == SOCKET_ERROR) {
			printf("    [-] ������ � recv(): %d\n", WSAGetLastError());
			closeAll(&ClientSocket);
			return 1;
		}

		if (buf[0] == 0x01) {
			continue;
		}

		if (buf[0] == 0x02) {
			printf("Name\t\t\t\t|\tPID\t|\tPPID\t|  cntThreads   |  pcPriClassBase\n");

			while (true) {
				ZeroMemory(&buf, sizeof(buf));
				packet_size = recv(ClientSocket, buf, 512, 0);

				if (packet_size == SOCKET_ERROR) {
					printf("    [-] ������ � recv(): %d\n", WSAGetLastError());
					closeAll(&ClientSocket);
					return 1;
				}

				if (buf[0] == 0x01) {
					break;
				}
				
				printf("%s\n", buf);
			}
			continue;
		}

		printf("%s\n", buf);
	}
	

	closeAll(&ClientSocket);

	printf("[=] ������ ��������\n");
	return 0;
}

