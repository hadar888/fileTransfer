#ifndef PACKET_H
#define PACKET_h

#include "Header.h"
#include "Payload.h"

class Packet {
public:
	Header header;
	Payload *payload;

	Packet(){}

	Packet(Header header, Payload* payload) {
		this->header = header;
		this->payload = payload;
	}

	Packet(char* buffer) {
		char version;
		short msgCode;
		int payloadSize;
		unsigned char clientId[16];

		memcpy(&version, &buffer[0], sizeof(version));
		memcpy(&msgCode, &buffer[1], sizeof(short));
		memcpy(&payloadSize, &buffer[3], sizeof(int));
		memcpy(&clientId, &buffer[7], sizeof(char) * 16);
		
		Header serverHeader(version, msgCode, payloadSize);
		RegisterOkPayload registerOkPayload(clientId);

		this->header = serverHeader;
		this->payload = &registerOkPayload;
	}

	std::string packetToJsonString() {
		return "{\"Header\": " + header.headerToJsonString() + ", "
			"\"Payload\": " + (*payload).payloadToJsonString() + "}";
	}
};

#endif
