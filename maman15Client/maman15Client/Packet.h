#ifndef PACKET_H
#define PACKET_h

#include "Header.h"
#include "Payload.h"

enum MsgsCodes {
	Register = 1100, SendPublicKey = 1101, SendFile = 1103, CrcOk = 1104,
	CrcNotOk = 1105, CrcNotOk4 = 1106, RegisterOk = 2100, GetAes = 2102, FileOkAndCrc = 2103, GotMsg = 2104
};

class Packet {
public:
	Header* header;
	Payload* payload;

	Packet(){}

	Packet(Header* header, Payload* payload) {
		this->header = header;
		this->payload = payload;
	}

	Packet(char* buffer) {
		char version;
		short msgCode;
		int payloadSize;

		memcpy(&version, &buffer[0], sizeof(version));
		memcpy(&msgCode, &buffer[1], sizeof(short));
		memcpy(&payloadSize, &buffer[3], sizeof(int));
		Header serverHeader(version, msgCode, payloadSize);
		
		switch (serverHeader.code)
		{
		case RegisterOk: 
		{
			break;
		}

		case GetAes:
		{
			unsigned char clientId[UUID_LENGTH];
			//the size of publicEncryptedAesKey shuold not be 16, 16 is the size of the not encrypted key
			//the size of publicEncryptedAesKey shuold be serverHeader.payloadSize - 16
			unsigned char publicEncryptedAesKey[16];

			memcpy(&clientId, &buffer[serverResponseHeaderSize], sizeof(char) * UUID_LENGTH);
			memcpy(&publicEncryptedAesKey, &buffer[serverResponseHeaderSize + UUID_LENGTH], sizeof(char) * 16);
			//GetAesPayload getAesPayload(clientId, publicEncryptedAesKey);
			//this->payload = &registerOkPayload;

			break;
		}

		case FileOkAndCrc:
		{
			unsigned char clientId[UUID_LENGTH];
			unsigned int fileSize;
			unsigned char fileName[FILE_PATH_LENGTH];
			unsigned int cksum;

			memcpy(&clientId, &buffer[serverResponseHeaderSize], sizeof(char) * UUID_LENGTH);
			memcpy(&fileSize, &buffer[serverResponseHeaderSize + UUID_LENGTH], sizeof(int));
			memcpy(&fileName, &buffer[serverResponseHeaderSize + UUID_LENGTH + sizeof(int)], sizeof(char) * FILE_PATH_LENGTH);
			memcpy(&cksum, &buffer[serverResponseHeaderSize + UUID_LENGTH + sizeof(int) + FILE_PATH_LENGTH], sizeof(int));
			//FileOkAndCrcPayload fileOkAndCrc(clientId, fileSize, fileName, cksum);
			//this->payload = &registerOkPayload;

			break;
		}

		case GotMsg:
		{
			break;
		}

		default:
			printf("ERROR: unknown mgs code from server or protocol format problem\n");
			break;
		}

		this->header = &serverHeader;
	}
};

class ClientPacket : public Packet {
public:
	ClientHeader* header;

	ClientPacket(ClientHeader* header, Payload* payload) {
		this->header = header;
		this->payload = payload;
	}

	void packetToBuffer(char* packetDataToSend) {
		(*header).headerToBuffer(packetDataToSend);
		(*payload).payloadToBuffer(&packetDataToSend[23]);
	}
};

class ServerRegisterOkResponsePacket : public Packet {
public:
	RegisterOkPayload payload;

	ServerRegisterOkResponsePacket(char* buffer) {
		unsigned char clientId[UUID_LENGTH];
		memcpy(clientId, &buffer[1 + 2 + 4], sizeof(char) * UUID_LENGTH);
		RegisterOkPayload registerOkPayload(clientId);
		this->payload = registerOkPayload;
	}
};

class ServerGotAesEncreptedKeyPacket : public Packet {
public:
	GotAesEncreptedKeyPayload payload;

	ServerGotAesEncreptedKeyPacket(char* buffer) {
		unsigned char clientId[UUID_LENGTH] = { 0 };
		char aesEncreptedKey[128] = { 0 };
		int encreptedKeyLen;

		memcpy(clientId, &buffer[serverResponseHeaderSize], sizeof(char) * UUID_LENGTH);
		memcpy(&encreptedKeyLen, &buffer[3], sizeof(int));
		encreptedKeyLen = encreptedKeyLen - sizeof(clientId);
		memcpy(&aesEncreptedKey, &buffer[23], sizeof(char) * encreptedKeyLen);

		GotAesEncreptedKeyPayload gotAesEncreptedKeyPayload(clientId, aesEncreptedKey, encreptedKeyLen);
		this->payload = gotAesEncreptedKeyPayload;
	}
};

class ServerGotFilePacket : public Packet {
public:
	GotFilePayload payload;

	ServerGotFilePacket(char buffer[]) {
		unsigned char clientId[UUID_LENGTH] = { 0 };
		unsigned int fileSize = 0;
		unsigned char fileName[FILE_PATH_LENGTH] = { 0 };
		unsigned int cksum = 0;

		memcpy(clientId, &buffer[serverResponseHeaderSize], sizeof(char) * UUID_LENGTH);
		memcpy(&fileSize, &buffer[serverResponseHeaderSize + UUID_LENGTH], sizeof(int));
		memcpy(fileName, &buffer[serverResponseHeaderSize + UUID_LENGTH + sizeof(int)], sizeof(char) * FILE_PATH_LENGTH);
		memcpy(&cksum, &buffer[serverResponseHeaderSize + UUID_LENGTH + sizeof(int) + FILE_PATH_LENGTH], sizeof(int));

		GotFilePayload gotFilePayload(clientId, fileSize, fileName, cksum);
		this->payload = gotFilePayload;
	}
};

#endif
