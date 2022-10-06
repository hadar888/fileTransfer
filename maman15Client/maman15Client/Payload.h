#ifndef PAYLOAD_H
#define PAYLOAD_H

#include<string>

class Payload {
public:
	virtual std::string payloadToJsonString() {
		return "payloadToJsonString base class\n";
	}
};

class RegisterPayload : public Payload {
public:
	std::string name;

	RegisterPayload(std::string name) {
		this->name = name;
	}

	std::string payloadToJsonString() {
		return "\"{"
			"'Name': '" + this->name + "'"
			"}\"";
	}
};

class RegisterOkPayload : public Payload {
public:
	unsigned char* name;

	RegisterOkPayload(unsigned char* name) {
		this->name = name;
	}
};

#endif 