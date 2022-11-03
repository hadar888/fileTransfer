#ifndef TRANSFER_ME_H
#define TRANSFER_ME_H

#define NAME_LENGTH 255
#define FILE_PATH_LENGTH 255
#define UUID_LENGTH 16
#define UUID_ASCII_LENGTH 32

#include <fstream>
#include "Base64Wrapper.h"
#include <iomanip>

using namespace std;

class TransferMeInfo {
public:
	string serverIp;
	string serverPort;
	char name[NAME_LENGTH] = { 0 };
	char fileToSendName[FILE_PATH_LENGTH] = { 0 };
	unsigned char uuid[UUID_LENGTH] = { 0 };
	string privateKey;

	TransferMeInfo() {
		ifstream transferFile("transfer.info");
		if (transferFile.is_open()) {
			getTransferInfo(&transferFile);
		}
		else {
			printf("ERROR: Transfer file was not found");
			exit(-1);
		}

		ifstream meFile("me.info");
		if (meFile.is_open()) {
			getMeInfo(&meFile);
		}
	}

private:
	void getTransferInfo(ifstream* transferFile) {
		string nameString;
		string fileNameString;

		getline(*transferFile, this->serverIp, ':');
		getline(*transferFile, this->serverPort);
		getline(*transferFile, nameString);
		memcpy(this->name, nameString.c_str(), min(nameString.size(), NAME_LENGTH));
		getline(*transferFile, fileNameString);
		ifstream isfilePathValid(fileNameString);
		if (!isfilePathValid) {
			printf("ERROR: file name is not valid\n");
			exit(-1);
		}
		memcpy(this->fileToSendName, fileNameString.c_str(), min(fileNameString.size(), NAME_LENGTH));
	}

	void getMeInfo(ifstream* meFile) {
		string nameString;
		string uuidString;
		unsigned char uuidToFix[UUID_ASCII_LENGTH] = { 0 };

		getline(*meFile, nameString);
		memcpy(this->name, nameString.c_str(), min(nameString.size(), NAME_LENGTH));

		getline(*meFile, uuidString);
		if (uuidString.size() != UUID_ASCII_LENGTH) {
			printf("ERROR: uuid in me.info file is to short or long");
			exit(-1);
		}
		memcpy(uuidToFix, uuidString.c_str(), uuidString.size());
		asciiUuidToByteArrayUuid(uuidToFix, this->uuid);

		string privateKeyEencoded;
		getline(*meFile, privateKeyEencoded);
		this->privateKey = Base64Wrapper::decode(privateKeyEencoded);
	}

	void asciiUuidToByteArrayUuid(unsigned char uuidToFix[UUID_ASCII_LENGTH], unsigned char uuid[UUID_LENGTH]) {
		for (int i = 0; i < UUID_ASCII_LENGTH; i += 2) {
			if (!isxdigit(uuidToFix[i]) || !isxdigit(uuidToFix[i + 1])) {
				printf("ERROR: uuid in me.info file is not valid");
				exit(-1);
			}
			uuidToFix[i] = tolower(uuidToFix[i]);
			uuidToFix[i + 1] = tolower(uuidToFix[i + 1]);
			//from hex-hex to byte
			int c1 = (uuidToFix[i] >= 'a') ? (uuidToFix[i] - 'a' + 10) : (uuidToFix[i] - '0');
			int c2 = (uuidToFix[i + 1] >= 'a') ? (uuidToFix[i + 1] - 'a' + 10) : (uuidToFix[i + 1] - '0');
			c1 <<= 4;
			uuid[i / 2] = c1 | c2;
		}
	}

public:
	void createMeInfoFile() {
		ofstream out("me.info");
		out << this->name;
		out << "\n";

		//save clientId into me.info file
		for (int i = 0; i < UUID_LENGTH; i++) {
			out << hex << setw(2) << setfill('0') << int(this->uuid[i]);
		}
		out << "\n";

		//generate rsa private key
		RSAPrivateWrapper rsapriv;
		this->privateKey = rsapriv.getPrivateKey();
		string privateKeyBase64 = Base64Wrapper::encode(rsapriv.getPrivateKey());
		
		//save private key into me.info file
		privateKeyBase64.erase(remove(privateKeyBase64.begin(), privateKeyBase64.end(), '\n'), privateKeyBase64.cend());
		out << privateKeyBase64;
		out.close();
	}
};

#endif