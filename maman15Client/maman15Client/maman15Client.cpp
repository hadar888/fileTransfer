#include "pch.h"

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "crc32.cpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include "TransferInfo.h"
#include "Header.h"
#include "Payload.h"
#include "Packet.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

int connectToServer(TransferInfo transferInfo) {
	WSADATA Data;
	int sock = 0;
	struct sockaddr_in serv_addr;

	WSAStartup(MAKEWORD(2, 2), &Data); // 2.2 version
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	short port;
	sscanf_s(transferInfo.serverPort.c_str(), "%hi", &port);
	serv_addr.sin_port = htons(port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, transferInfo.serverIp.c_str(), &serv_addr.sin_addr) <= 0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}

	return sock;
}

string hexify(const unsigned char* buffer, unsigned int length){
	stringstream ss;
	ios::fmtflags f(cout.flags());
	for (size_t i = 0; i < length; i++)
		ss << setfill('0') << setw(2) << (0xFF & buffer[i]) << " ";
	cout << endl;
	cout.flags(f);

	return ss.str();
}

int const maxFailAllow = 3;

bool sendPacketWithFail(int sock, ClientPacket packet, char* responseBuffer, int responseBufferLen) {
	char buffer[1024] = { 0 };
	packet.packetToJsonString(buffer);

	bool isMsgSucceeded = false;
	int failCount = 0;
	do {
		send(sock, buffer, 23 + packet.header->payloadSize, 0);
		printf("%d msg sent\n", packet.header->code);
		int valread = recv(sock, buffer, 1024, 0);
		Packet returnMsg(buffer);
		std::memcpy(responseBuffer, buffer, sizeof(char) * responseBufferLen);

		if (strcmp(buffer, "FAILD") == 0) {
			failCount++;
			printf("server responded with an error\n");
		}
		else {
			printf("retuen msg code: %d\n\n", returnMsg.header->code);
			isMsgSucceeded = true;
		}

	} while (failCount < maxFailAllow && !isMsgSucceeded);
	if (failCount == maxFailAllow) {
		printf("FATAL: Fail to send %d msg\n", packet.header->code);
		return false;
	}
	return true;
}

int main(int argc, char const *argv[])
{
	TransferInfo transferInfo;
	int sock = connectToServer(transferInfo);
	if (sock == -1) {
		return -1;
	}

	char buffer[1024] = { 0 };

	//TODO: check if user registered

	//create packet for register
	char emptyClientId[] = "0000000000000000";
	ClientHeader clientHeader(emptyClientId, 3, Register, 255);
	RegisterPayload registerPayload(transferInfo.name);
	ClientPacket registerPacket(&clientHeader, &registerPayload);

	char registerResponseBuffer[23] = { 0 };
	if (!sendPacketWithFail(sock, registerPacket, registerResponseBuffer, 23)) {
		printf("The username maybe in use already");
		return -1;
	}

	char clientIdFromServer[16];
	ServerRegisterOkResponsePacket serverRegisterOkResponsePacket(registerResponseBuffer);
	std::memcpy(clientIdFromServer, serverRegisterOkResponsePacket.payload.clientId, sizeof(char) * 16);
	std::memcpy(&clientHeader.clientId, &clientIdFromServer, sizeof(char) * 16);
	clientHeader.code = SendPublicKey;
	clientHeader.payloadSize = 255 + 160;

	RSAPrivateWrapper rsapriv;
	string pubkey = rsapriv.getPublicKey();

	SendPublicKeyPayload sendPublicKeyPayload(transferInfo.name, pubkey.c_str());
	ClientPacket publicKeyPacket(&clientHeader, &sendPublicKeyPayload);

	char publicKeyResponseBuffer[1 + 2 + 4 + 16 + 128] = { 0 };
	if (!sendPacketWithFail(sock, publicKeyPacket, publicKeyResponseBuffer, 1 + 2 + 4 + 16 + 128)) {
		printf("Faild to get encrepted AES key");
		return -1;
	}
	ServerGotAesEncreptedKeyPacket serverGotAesEncreptedKeyPacket(publicKeyResponseBuffer);

	// decrypt AES key, with private RSA key (save the AES key into aesKey)
	std::string encreptedAesKey(serverGotAesEncreptedKeyPacket.payload.encreptedKey);
	std::string aesKey = rsapriv.decrypt(encreptedAesKey.c_str(), 128);
	

	bool isCrsOk = false;
	int failCount = 0;
	do {
		AESWrapper aes(reinterpret_cast<const unsigned char*>(aesKey.c_str()), 16);
		// TODO: fix first 16 chars bug
		std::string paddingForBug = "aaaaaaaaaaaaaaaa";
		const char* fileData = "my name is hey my name is hadar text text hadar text text text textt hey my name is hadar text text hadar text text text textt hey my name is hadar text text hadar";
		std::string fileDataToSend = paddingForBug + fileData;
		char fileName[255] = "fileName";
		std::string encryptedFileData = aes.encrypt(fileDataToSend.c_str(), fileDataToSend.length());

		clientHeader.code = SendFile;
		clientHeader.payloadSize = 16 + 4 + 255 + encryptedFileData.length();
		SendFilePayload sendFilePayload(clientHeader.clientId, encryptedFileData.length(), fileName, encryptedFileData.c_str());

		ClientPacket filePacket(&clientHeader, &sendFilePayload);
		
		char fileResponseBuffer[1 + 2 + 4 + 16 + 4 + 255 + 4] = { 0 };
		if (!sendPacketWithFail(sock, filePacket, fileResponseBuffer, 1 + 2 + 4 + 16 + 4 + 255 + 4)) {
			printf("Faild to crc from server");
			return -1;
		}
		ServerGotFilePacket serverGotFilePacket(fileResponseBuffer);

		uint32_t table[256];
		crc32::generate_table(table);
		uint32_t crc = crc32::update(table, 0, fileData, strlen(fileData));

		CrcMsgPayload crcMsgPayload(clientHeader.clientId, fileName);
		char crcResponseBuffer[1 + 2 + 4] = { 0 };
		clientHeader.payloadSize = 16 + 255;
		
		if (crc == serverGotFilePacket.payload.cksum) {
			printf("Checksum ok\n");

			isCrsOk = true;
			clientHeader.code = CrcOk;
			ClientPacket crcPacket(&clientHeader, &crcMsgPayload);

			if (!sendPacketWithFail(sock, crcPacket, crcResponseBuffer, 1 + 2 + 4)) {
				printf("Faild to send crc ok msg to server");
				return -1;
			}
		}
		else {
			failCount++;
			printf("Checksum failed");

			if (failCount != maxFailAllow) {
				clientHeader.code = CrcNotOk;
				ClientPacket failCrcPacket(&clientHeader, &crcMsgPayload);

				if (!sendPacketWithFail(sock, failCrcPacket, crcResponseBuffer, 1 + 2 + 4)) {
					printf("Faild to send faild crc msg to server");
					return -1;
				}
			}
			else {
				clientHeader.code = CrcNotOk4;
				ClientPacket failCrcPacket(&clientHeader, &crcMsgPayload);

				if (!sendPacketWithFail(sock, failCrcPacket, crcResponseBuffer, 1 + 2 + 4)) {
					printf("Faild to send faild crc on the fourth time msg to server");
					return -1;
				}
			}
		}
	} while (!isCrsOk && failCount < maxFailAllow);

	WSACleanup();
	return 0;
}
