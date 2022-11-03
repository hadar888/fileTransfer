#include "pch.h"

#include <stdio.h>
#include <ws2tcpip.h>
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "crc32.cpp"
#include "TransferMeInfo.h"
#include "Packet.h"
#include "Base64Wrapper.h"
#include <iomanip>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;
const unsigned int clientVersion = 3;

int connectToServer(TransferMeInfo transferMeInfo) {
	WSADATA Data;
	int sock = 0;
	struct sockaddr_in serv_addr;

	WSAStartup(MAKEWORD(2, 2), &Data);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("ERROR: Socket creation error\n");
		exit(-1);
	}

	serv_addr.sin_family = AF_INET;
	short port;
	sscanf_s(transferMeInfo.serverPort.c_str(), "%hi", &port);
	serv_addr.sin_port = htons(port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, transferMeInfo.serverIp.c_str(), &serv_addr.sin_addr) <= 0) {
		printf("ERROR: Invalid address/ Address not supported\n");
		exit(-1);
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("Error: Connection Failed, the server migth not working or the port is not valid\n");
		exit(-1);
	}

	return sock;
}

int const maxFailAllow = 3;
bool sendPacketWithFail(int sock, ClientPacket packet, char* responseBuffer, int responseBufferLen) {
	char *buffer = (char*)calloc(23 + packet.header->payloadSize, sizeof(char));
	packet.packetToBuffer(buffer);

	bool isMsgSucceeded = false;
	int failCount = 0;
	do {
		printf("Tyring to send %d msg...\n", packet.header->code);
		send(sock, buffer, 23 + packet.header->payloadSize, 0);
		printf("%d msg sent\nWaiting for response msg from the server...\n", packet.header->code);
		int valread = recv(sock, buffer, 1024, 0); // chceck this 1024!
		string responseBufferString(buffer);

		if (strcmp(responseBufferString.substr(0, 5).c_str(), "FAILD") == 0) {
			failCount++;
			printf("server responded with an error\n");
		}
		else {
			Packet returnMsg(buffer);
			memcpy(responseBuffer, buffer, sizeof(char) * responseBufferLen);

			printf("retuen msg code: %d\n\n", returnMsg.header->code);
			isMsgSucceeded = true;
		}

	} while (failCount < maxFailAllow && !isMsgSucceeded);
	if (failCount == maxFailAllow) {
		printf("\nFATAL: Fail to get response for %d msg\n", packet.header->code);
		WSACleanup();
		return false;
	}
	return true;
}

int main(int argc, char const *argv[])
{
	TransferMeInfo transferMeInfo;
	int sock = connectToServer(transferMeInfo);
	ClientHeader clientHeader(transferMeInfo.uuid, clientVersion);

	if (transferMeInfo.uuid[0] == '\0') {
		printf("--Register--\n");
		//create packet for register
		clientHeader.code = Register;
		clientHeader.payloadSize = FILE_PATH_LENGTH;

		RegisterPayload registerPayload(transferMeInfo.name);
		ClientPacket registerPacket(&clientHeader, &registerPayload);

		char registerResponseBuffer[serverResponseHeaderSize + UUID_LENGTH] = { 0 };
		if (!sendPacketWithFail(sock, registerPacket, registerResponseBuffer, serverResponseHeaderSize + UUID_LENGTH)) {
			printf("The username maybe in use already\n");
			return -1;
		}

		ServerRegisterOkResponsePacket serverRegisterOkResponsePacket(registerResponseBuffer);
		memcpy(&transferMeInfo.uuid, serverRegisterOkResponsePacket.payload.clientId, sizeof(char) * UUID_LENGTH);
		transferMeInfo.createMeInfoFile();
	}

	printf("--Send Public Key--\n");
	//create packet for sending public key
	clientHeader.code = SendPublicKey;
	clientHeader.payloadSize = NAME_LENGTH + PUBLIC_KEY_LENGTH;
	RSAPrivateWrapper rsapriv(transferMeInfo.privateKey);
	string pubkey = rsapriv.getPublicKey();
	
	SendPublicKeyPayload sendPublicKeyPayload(transferMeInfo.name, pubkey.c_str());
	ClientPacket publicKeyPacket(&clientHeader, &sendPublicKeyPayload);

	char publicKeyResponseBuffer[serverResponseHeaderSize + UUID_LENGTH + 128] = { 0 };
	if (!sendPacketWithFail(sock, publicKeyPacket, publicKeyResponseBuffer, serverResponseHeaderSize + UUID_LENGTH + 128)) {
		printf("Faild to get encrepted AES key\n");
		return -1;
	}
	ServerGotAesEncreptedKeyPacket serverGotAesEncreptedKeyPacket(publicKeyResponseBuffer);

	printf("--Encrypt File With AES--\n");
	// decrypt AES key with private RSA key
	string aesKey = rsapriv.decrypt(serverGotAesEncreptedKeyPacket.payload.encreptedKey, 128);

	bool isCrsOk = false;
	int failCount = 0;
	do {
		AESWrapper aes(reinterpret_cast<const unsigned char*>(aesKey.c_str()), 16);

		ifstream t(transferMeInfo.fileToSendName);
		stringstream fileData;
		fileData << t.rdbuf();
		
		string fileDataToSend = fileData.str();
		string encryptedFileData = aes.encrypt(fileDataToSend.c_str(), fileDataToSend.size());

		printf("--Send Encrypted File--\n");
		clientHeader.code = SendFile;
		clientHeader.payloadSize = UUID_LENGTH + 4 + FILE_PATH_LENGTH + encryptedFileData.size();
		SendFilePayload sendFilePayload(clientHeader.clientId, encryptedFileData.size(), transferMeInfo.fileToSendName, encryptedFileData.c_str());
		
		ClientPacket filePacket(&clientHeader, &sendFilePayload);
		
		char fileResponseBuffer[1 + 2 + 4 + UUID_LENGTH + 4 + FILE_PATH_LENGTH + 4] = { 0 };
		if (!sendPacketWithFail(sock, filePacket, fileResponseBuffer, 1 + 2 + 4 + UUID_LENGTH + 4 + FILE_PATH_LENGTH + 4)) {
			printf("Faild to get crc from server\n");
			return -1;
		}
		ServerGotFilePacket serverGotFilePacket(fileResponseBuffer);

		uint32_t table[256];
		crc32::generate_table(table);
		string fileDataString = fileData.str();
		uint32_t crc = crc32::update(table, 0, fileDataString.c_str(), fileDataString.size());

		CrcMsgPayload crcMsgPayload(clientHeader.clientId, transferMeInfo.fileToSendName);
		char crcResponseBuffer[1 + 2 + 4] = { 0 };
		clientHeader.payloadSize = UUID_LENGTH + FILE_PATH_LENGTH;
		
		if (crc == serverGotFilePacket.payload.cksum) {
			printf("Checksum ok\n");

			isCrsOk = true;
			clientHeader.code = CrcOk;
			ClientPacket crcPacket(&clientHeader, &crcMsgPayload);

			if (!sendPacketWithFail(sock, crcPacket, crcResponseBuffer, 1 + 2 + 4)) {
				printf("Faild to send crc ok msg to server\n");
				return -1;
			}
		}
		else {
			failCount++;
			printf("Checksum failed\n");

			if (failCount != maxFailAllow) {
				clientHeader.code = CrcNotOk;
				ClientPacket failCrcPacket(&clientHeader, &crcMsgPayload);

				if (!sendPacketWithFail(sock, failCrcPacket, crcResponseBuffer, 1 + 2 + 4)) {
					printf("Faild to send faild crc msg to server\n");
					return -1;
				}
			}
			else {
				clientHeader.code = CrcNotOk4;
				ClientPacket failCrcPacket(&clientHeader, &crcMsgPayload);

				if (!sendPacketWithFail(sock, failCrcPacket, crcResponseBuffer, 1 + 2 + 4)) {
					printf("Faild to send faild crc on the fourth time msg to server\n");
					return -1;
				}
			}
		}
	} while (!isCrsOk && failCount < maxFailAllow);

	WSACleanup();
	return 0;
}
