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
#include <zlib.h>
#include "TransferInfo.h"
#include "Header.h"
#include "Payload.h"
#include "Packet.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

int connectToServer(TransferInfo transferInfo) {
	WSADATA Data;
	int sock = 0, valread;
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

bool sendPacketWithFail(int sock, Packet packet, char* responseBuffer) {
	char buffer[1024] = { 0 };

	string packetJsonString = packet.packetToJsonString();
	char *msgPtr = &packetJsonString[0];

	bool isMsgSucceeded = false;
	int failCount = 0;
	do {
		send(sock, msgPtr, strlen(msgPtr), 0);
		printf("%d msg sent\n", packet.header->code);
		int valread = recv(sock, buffer, 1024, 0);
		Packet returnMsg(buffer);
		std::memcpy(responseBuffer, buffer, sizeof(char) * 16);

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

	int valread;
	char buffer[1024] = { 0 };

	//create packet for register
	char emptyClientId[] = "empty";
	ClientHeader clientHeader(emptyClientId, 3, Register, sizeof(char) * transferInfo.name.length());
	RegisterPayload registerPayload(transferInfo.name.c_str());
	Packet registerPacket(&clientHeader, &registerPayload);

	char registerResponseBuffer[23] = { 0 };
	if (!sendPacketWithFail(sock, registerPacket, registerResponseBuffer)) {
		printf("The username maybe in use already");
		return -1;
	}

	ServerRegisterOkResponsePacket serverRegisterOkResponsePacket(registerResponseBuffer);
	std::memcpy(clientHeader.clientId, serverRegisterOkResponsePacket.payload->clientId, sizeof(clientHeader.clientId));
	clientHeader.code = SendPublicKey;
	clientHeader.payloadSize = 255 + 160;

	RSAPrivateWrapper rsapriv;
	string pubkey = rsapriv.getPublicKey();
	string pubkeyHex = hexify(reinterpret_cast<const unsigned char*>(pubkey.c_str()), pubkey.length());

	SendPublicKeyPayload sendPublicKeyPayload(transferInfo.name.c_str(), pubkeyHex.c_str());
	Packet publicKeyPacket(&clientHeader, &sendPublicKeyPayload);

	char publicKeyResponseBuffer[16 + 255] = { 0 }; // should not be 255, should be the size of AES key encrepted
	if (!sendPacketWithFail(sock, publicKeyPacket, publicKeyResponseBuffer)) {
		printf("Faild to get encrepted AES key");
		return -1;
	}

	/*
	valread = recv(sock, buffer, 1024, 0);
	printf("retuen msg: %s\n\n", buffer);
	//TODO: decrypt public AES key, with private RSA key (save the public AES key into publicAESKey)

	bool isCrsOk = false;
	int counter = 0;
	while (!isCrsOk && counter < 3) {
		//TODO: encrypt file data with public AES key
		//AESWrapper aes((unsigned char*)publicAESKey, 16);
		//string ciphertext = aes.encrypt(msgToSend.c_str(), msgToSend.length());
		string ciphertextHex = "should be encrypted file data"; //TODO: replace with this line: hexify(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());

		string fileData = "{\"request_type\": 3, \"file\": \"" + ciphertextHex + "\"}";
		send(sock, fileData.c_str(), fileData.length(), 0);
		printf("file data sent\n");
		valread = recv(sock, buffer, 1024, 0);
		printf("retuen msg: %s\n\n", buffer);

		uint32_t table[256];
		crc32::generate_table(table);
		uint32_t crc = crc32::update(table, 0, ciphertextHex.c_str(), ciphertextHex.length());

		//convert crc to string
		ostringstream a;
		a << crc;
		string crcString = a.str();

		if (crcString == buffer) {
			isCrsOk = true;
			char crcOk[] = "{\"request_type\": 5, \"msg\": \"crc ok\", \"file_name\": \"hadarTest1.txt\"}";
			send(sock, crcOk, strlen(crcOk), 0);
			printf("crc ok msg sent\n");
		}
		else {
			printf("Checksum failed");
			if (counter + 1 < 3) {
				printf(", the system will try to send the file again %d more times\n\n", 2 - counter);
			}
		}
		counter++;
	}
	if (counter == 3) {
		char abort[] = "{\"request_type\": 4, \"msg\": \"abort msg\"}";
		send(sock, abort, strlen(abort), 0);
		printf("abort msg sent\n");
	}

	*/

	WSACleanup();
	return 0;

}