#ifndef HEADER_H
#define HEADER_H

#include <string>

using namespace std;

const unsigned int serverResponseHeaderSize = sizeof(char) + sizeof(short) + sizeof(int);

class Header {
public:
	char version;
	short code;
	int payloadSize;

	Header(){}
	
	Header(char version, short code, int payloadSize) {
		this->code = code;
		this->payloadSize = payloadSize;
		this->version = version;
	}

	string headerToBuffer() {
		return "\"{"
			"'Version': " + to_string(this->version) + ", "
			"'Code': " + to_string(this->code) + ", "
			"'Payload size': " + to_string(this->payloadSize) +
			"}\"";
	}
};

class ClientHeader: public Header {
public:
	unsigned char clientId[UUID_LENGTH];

	ClientHeader(unsigned char clientId[UUID_LENGTH], char version) {
		memcpy(this->clientId, clientId, sizeof(this->clientId));
		this->version = version;
	}

	void headerToBuffer(char* headerDataToSend) {
		memcpy(&headerDataToSend[0], &this->clientId, sizeof(char) * UUID_LENGTH);
		memcpy(&headerDataToSend[UUID_LENGTH], &this->version, sizeof(char));
		memcpy(&headerDataToSend[17], &this->code, sizeof(short));
		memcpy(&headerDataToSend[19], &this->payloadSize, sizeof(int));
	}

	void setClientId(char clientId[UUID_LENGTH]) {
		memcpy(this->clientId, clientId, sizeof(this->clientId));
	}
};

#endif