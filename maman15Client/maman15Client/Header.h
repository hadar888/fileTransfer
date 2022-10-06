#ifndef HEADER_H
#define HEADER_H

#include <string>

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

	std::string headerToJsonString() {
		return "\"{"
			"'Version': " + std::to_string(this->version) + ", "
			"'Code': " + std::to_string(this->code) + ", "
			"'Payload size': " + std::to_string(this->payloadSize) +
			"}\"";
	}
};

class ClientHeader: public Header {
public:
	std::string clientId;

	ClientHeader(std::string clientId, char version, short code, int payloadSize) {
		this->clientId = clientId;
		this->code = code;
		this->payloadSize = payloadSize;
		this->version = version;
	}

	std::string headerToJsonString() {
		return "\"{"
			"'Client ID': '" + this->clientId + "', "
			"'Version': " + std::to_string(this->version) + ", "
			"'Code': " + std::to_string(this->code) + ", "
			"'Payload size': " + std::to_string(this->payloadSize) +
			"}\"";
	}
};

#endif