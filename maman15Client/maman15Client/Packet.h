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

		case GetAes:
		{
			unsigned char clientId[16];
			//the size of publicEncryptedAesKey shuold not be 16, 16 is the size of the not encrypted key
			//the size of publicEncryptedAesKey shuold be serverHeader.payloadSize - 16
			unsigned char publicEncryptedAesKey[16];

			memcpy(&clientId, &buffer[7], sizeof(char) * 16);
			memcpy(&publicEncryptedAesKey, &buffer[23], sizeof(char) * 16);
			//GetAesPayload getAesPayload(clientId, publicEncryptedAesKey);
			//this->payload = &registerOkPayload;

			break;
		}

		case FileOkAndCrc:
		{
			unsigned char clientId[16];
			unsigned int fileSize;
			unsigned char fileName[255];
			unsigned int cksum;

			memcpy(&clientId, &buffer[7], sizeof(char) * 16);
			memcpy(&fileSize, &buffer[23], sizeof(int));
			memcpy(&fileName, &buffer[27], sizeof(char) * 255);
			memcpy(&cksum, &buffer[283], sizeof(int));
			//FileOkAndCrcPayload fileOkAndCrc(clientId, fileSize, fileName, cksum);
			//this->payload = &registerOkPayload;

			break;
		}

		case GotMsg:
		{
			//unclear
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

	void packetToJsonString(char* packetDataToSend) {
		(*header).headerToJsonString(packetDataToSend);
		(*payload).payloadToJsonString(&packetDataToSend[23]);
	}
};

class ServerRegisterOkResponsePacket : public Packet {
public:
	RegisterOkPayload payload;

	ServerRegisterOkResponsePacket(char* buffer) {
		unsigned char clientId[16];
		memcpy(clientId, &buffer[7], sizeof(char) * 16);
		RegisterOkPayload registerOkPayload(clientId);
		this->payload = registerOkPayload;
	}
};

class ServerGotAesEncreptedKeyPacket : public Packet {
public:
	GotAesEncreptedKeyPayload payload;

	ServerGotAesEncreptedKeyPacket(char* buffer) {
		unsigned char clientId[16] = { 0 };
		char aesEncreptedKey[128] = { 0 }; //TODO: should not be 128!!!! 
		int encreptedKeyLen;

		memcpy(clientId, &buffer[7], sizeof(char) * 16);
		memcpy(&encreptedKeyLen, &buffer[3], sizeof(int));
		encreptedKeyLen = encreptedKeyLen - sizeof(clientId);
		memcpy(&aesEncreptedKey, &buffer[23], sizeof(char) * encreptedKeyLen);

		GotAesEncreptedKeyPayload gotAesEncreptedKeyPayload(clientId, aesEncreptedKey, encreptedKeyLen);
		this->payload = gotAesEncreptedKeyPayload;
	}
};

#endif
