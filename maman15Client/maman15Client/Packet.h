#ifndef PACKET_H
#define PACKET_h

#include "Header.h"
#include "Payload.h"

enum MsgsCodes {
	Register = 1100, SendPublicKey = 1101, sendFile = 1103, crcOk = 1104,
	crcNotOk = 1105, crcNotOk4 = 1106, registerOk = 2100, getAes = 2102, fileOkAndCrc = 2103, gotMsg = 2104
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
		case getAes:
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

		case fileOkAndCrc:
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

		case gotMsg:
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

	std::string packetToJsonString() {
		return "{\"Header\": " + (*header).headerToJsonString() + ", "
			"\"Payload\": " + (*payload).payloadToJsonString() + "}";
	}
};

class ServerRegisterOkResponsePacket: public Packet {
public:
	RegisterOkPayload* payload;

	ServerRegisterOkResponsePacket(char* buffer) {
		unsigned char clientId[16];

		memcpy(clientId, &buffer[7], sizeof(char) * 16);
		RegisterOkPayload registerOkPayload(clientId);
		this->payload = &registerOkPayload;
	}
};

#endif
