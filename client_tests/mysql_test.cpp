#include <iostream>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include<WS2tcpip.h>
#include<thread>
#include<sstream>
#include <string.h>
#include <mysql.h>
#include "openssl/applink.c"
#include "crypt.h"
#include <cassert>
#include <cstring>
#include <openssl/sha.h>
#include <iomanip>
#include<string>

#define _CRT_SECURE_NO_WARNINGS

#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "libmysql.lib")

#pragma warning (disable:4996)

//using namespace std;

int jj = 0;

//TwoVerifier()함수 처리부분
_openssl_BN g0_test, g1_test, y_test;
//EqualProver()함수 처리부분
_openssl_BN BETA_0, BETA_1;
//servertesk()함수 처리부분
_openssl_BN test_1, test_2, test_3;

int qstate;
_openssl_BN p, g, q, B, arrs_3[50000], arrs_4[50000], arr_pi[3], y, h, g0, g1, g2, e, v, gamma, S, arrs_beta[50000], r, z, arrs_pi_eq[3], H_test, arrs[100000], arrs_S[100000], arrs_k[100000], arrs_U[100000];
std::string str1, str2, str3, str4, str5, str6;
std::string sha256(const std::string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}
_openssl_BN T_temp;
_openssl_BN TwoVerifier(_openssl_BN p, _openssl_BN g0, _openssl_BN g1, _openssl_BN q, _openssl_BN y) {

	

	//p, y, beta (= arr_pi[0])
	str1 = p._bn2hex();
	str2 = y._bn2hex();
	str3 = arr_pi[0]._bn2hex();
	str4 = str1 + str2 + str3;
	str4 = sha256(str4);
	const char *cstr = str4.c_str();
	e._hex2bn(cstr);
	std::cout << str1 << std::endl;
	std::cout << str2 << std::endl;
	std::cout << str3 << std::endl;
	std::cout << "영접된 값 부분" << std::endl;
	std::cout << str4 << std::endl;
	std::cout << e._bn2hex() << std::endl;
	std::cout << arr_pi[0]._bn2hex() << std::endl;

	//v = g0^z0 * g1^z1 * y^e (mod p)
	g0_test = g0._exp(arr_pi[1], p);
	g1_test = g1._exp(arr_pi[2], p);
	y_test = y._exp(e, p);
	T_temp = g0_test._mul(g1_test, p);
	v = T_temp._mul(y_test, p);
	std::cout << v._bn2hex() << std::endl;

	if (arr_pi[0] == v) {
		std::cout << "성공입니당" << std::endl;
		return 1;
	}
	else {
		std::cout << "아닙니당" << std::endl;
		return 0;
	}

}

_openssl_BN EqualProver(_openssl_BN p, _openssl_BN g0, _openssl_BN g1, _openssl_BN q, _openssl_BN x, _openssl_BN y0, _openssl_BN y1) {
	r._randomInplace(q);
	
	BETA_0 = g0._exp(r, p);
	BETA_1 = g1._exp(r, p);

	

	
	str1 = p._bn2hex();
	str2 = y0._bn2hex();
	str3 = y1._bn2hex();
	str4 = BETA_0._bn2hex();
	str5 = BETA_1._bn2hex();
	str6 = str1 + str2 + str3 + str4 + str5;
	str6 = sha256(str6);
	const char *cstr = str6.c_str();
	e._hex2bn(cstr);

	_openssl_BN temped;
	temped = e._mul(x, q);
	z = r._sub(temped, q);
	arrs_pi_eq[0] = BETA_0;
	arrs_pi_eq[1] = BETA_1;
	arrs_pi_eq[2] = z;

	return 1;
}
_openssl_BN mm(-1);
int Server_Tesk() {


	//y = B * arrs_3[0]^-1 * arrs_4[0]^-1 (mod p)
	
	test_1 = arrs_3[0]._inv(p);
	test_2 = arrs_4[0]._inv(p);
	test_3 = test_1._mul(test_2, p);
	test_3 = test_3._mul(B, p);
	y = test_3;

	//h = g1 * g2 (mod p)
	h = g1._mul(g2, p);


	TwoVerifier(p, g0, h, q, y);

	gamma._randomInplace(q);
	S = g1._exp(gamma, p);

	//Line 7~8
	for (int i = 0; i < 5; i++) {
		arrs_beta[i] = arrs_3[i]._exp(gamma, p);
	}

	EqualProver(p, g1, arrs_3[0], q, gamma, S, arrs_beta[0]);

	//Line 9~11
	MYSQL* conn;
	MYSQL_ROW row;
	MYSQL_RES *res;
	conn = mysql_init(0);

	conn = mysql_real_connect(conn, "localhost", "root", "wndkdi123", "test_y", 3308, NULL, 0);

	int el = 0;
	

	if (conn) {
		puts("Successful connection to database!");

		std::string query = "SELECT * FROM test_y";
		const char* q = query.c_str();
		qstate = mysql_query(conn, q);
		if (!qstate) {
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				printf("ID: %s, Name: %s, Value: %s\n", row[0], row[1], row[2]);
				char* tests_1 = row[0];	//tests_1 -> y
				printf("%s\n", tests_1);

				H_test._hex2bn(tests_1);
				arrs[el] = H_test;
				printf("db내용\n");
				std::cout << el << std::endl;
				std::cout << arrs[el]._bn2hex() << std::endl;

				el++;


			}
		}
		else {
			std::cout << "Query failed: " << mysql_error(conn) << std::endl;
		}
	}
	else {
		puts("Connection to database has falied!");
	}

	//arrs[] <= yi, db내용

	for (int j = 0; j < 5; j++) {	//100000까지로 변경
		arrs_S[j] = g._exp(arrs[j], p);	//Sj = g^yi (mod p) <해쉬처리>
		arrs_k[j] = arrs_S[j]._exp(gamma, p);
		str1 = arrs_k[j]._bn2hex();
		str2 = arrs_S[j]._bn2hex();
		str3 = arrs[j]._bn2hex();
		str4 = str1 + str2 + str3;
		std::cout << "**&& 1" << std::endl;

		std::cout << str1 << std::endl;
		std::cout << "**&& 2" << std::endl;

		std::cout << str2 << std::endl;
		std::cout << "**&& 3" << std::endl;

		std::cout << str3 << std::endl;
		std::cout << "**&& 해쉬함수 들어가기 전 U값" << std::endl;

		std::cout << str4 << std::endl;
		str4 = sha256(str4);
		const char *cstr = str4.c_str();
		arrs_U[j]._hex2bn(cstr);
		std::cout << "tests 하는중! U의 값 출력" << std::endl;
		std::cout << arrs_U[j]._bn2hex() << std::endl;
	}




	std::cout << "hi hello" << std::endl;

	return 1;

}


int main() {
	using std::cout;
	using std::endl;



	/*
	printf("MySQL client Version : %s\n", mysql_get_client_info());

	MYSQL* conn;
	MYSQL_ROW row;
	MYSQL_RES *res;
	conn = mysql_init(0);

	conn = mysql_real_connect(conn, "localhost", "root", "wndkdi123", "_privatesety", 3308, NULL, 0);

	
	if (conn) {
		puts("Successful connection to database!");

		std::string query = "SELECT * FROM _privatesety";
		const char* q = query.c_str();
		qstate = mysql_query(conn, q);
		if (!qstate) {
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				//printf("ID: %s, Name: %s, Value: %s\n", row[0], row[1], row[2]);
				char* tests_1 = row[0];
				//printf("%s\n", tests_1);
			}
		}
		else {
			std::cout << "Query failed: " << mysql_error(conn) << std::endl;
		}
	}
	else {
		puts("Connection to database has falied!");
	}
	*/

	

	////////////////////////////////////////

	//INITIALIZE THE WINSOCK
	WSADATA some_kind_of_data;
	WSAStartup(MAKEWORD(2, 2), &some_kind_of_data);

	//CLIENT OBJECT
	struct CLIENT {
		char client_ip[256];
		SOCKET sock;
	};

	//CREATE A LIST OF CLIENTS
	std::vector<CLIENT> clients;

	//ACCEPT CONNECTION - THREAD 01
	std::thread accepter([=,&clients]() {
		///CREATE LISTENING SOCKET
		sockaddr_in listen_address;
		listen_address.sin_family = AF_INET;
		listen_address.sin_port = htons(666);
		listen_address.sin_addr.S_un.S_addr = INADDR_ANY;
		//CREATE THE SOCKET ITSELF
		SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, 0);
		//BIND THE ADRESS TO THE SOCKET
		bind(listen_socket, (sockaddr*)&listen_address, sizeof(listen_address));
		//SET THE SOCKET TO LISTENING MODE
		listen(listen_socket, SOMAXCONN);
		//STORE CLIENT IP
		sockaddr_in client_address;
		int client_address_size = sizeof(client_address);
		//TEMPORARY CLIENT SOCKET
		SOCKET client_socket;
		//USED FOR CHANGING SOCKETS TO NON_BLOCKING
		u_long non_blocking = true;

		while (true) {
			//CREATE TEMPORARY SOCKET
			client_socket = accept(listen_socket, (sockaddr*)&client_address, &client_address_size);
			if (client_socket != INVALID_SOCKET) { //IF CLIENT CONNECTED CORRECTLLY
												   //SET THE TEMPORARY SOCKET TO NON_BLOCKING
				ioctlsocket(client_socket, FIONBIO, &non_blocking);
				//CREATE NEW CLIENT OBJECT
				CLIENT new_client;
				//PUT SOCKET AND IP FROM TEMPORARY SOCKET TO NEW CLIENT OBJECT
				new_client.sock = client_socket;
				inet_ntop(AF_INET, &client_address.sin_addr, new_client.client_ip, 256);
				//ADD THE NEW CLIENT OBJECT TO THE LIST OF CLIENTS
				clients.push_back(new_client);
				//PRINT OUT THAT SOMEONE HAS CONNECTED
				std::cout << "Client " << new_client.client_ip << ":" << clients.size() - 1 << " Connected!" << std::endl;
			}
		}});

	




	//char* tmp_g;
	//char* tmp_p;
	//char* tmp_q;

	//RECEIVE MESSAGE - THREAD 03
	std::thread receiver([&clients]() {
		//BUFFER THAT STORES THE RECEIVED MESSAGE
		char buffer[2000];
		//std::string buffer;
		//std::string s;
		int ij = 0;
		int ij2 = 0;

		char* tmp;
		char t_p[2000];
		char t_q[2000];
		char t_g[2000];
		char t_B[2000];
		char t_alpa[2000];
		char t_omega[2000];
		char t_pi[2000];

		std::string str_tests;
		_openssl_BN sd;
		std::string hi = "hi";
		int S_counts = 1;
		int Server_count = 1;

		while (1) {
			
			while (Server_count) {
				//CYCKLE TROUGH ALL THE CLIENTS
				for (int i = 0; i < clients.size(); i++) {
					//DELETE THE OLD RECEIVED MESSAGE
					memset(buffer, 0, sizeof(buffer));

					//IF RECEIVED MESSAGE IS LONGER THEN ONE CHARACTER

					if (recv(clients[i].sock, buffer, sizeof(buffer), 0) >= 1) {
						tmp = strdup(buffer);
						//cout << tmp << endl;

						str_tests = str_tests + tmp;
						if (str_tests.find(hi) != std::string::npos) {
							cout << "i found!!" << endl;
							Server_count = 0;
						}

					}

				}

				if (Server_count == 0) {


					cout << "============" << endl;
					cout << str_tests << endl;

					int in_256 = 256;
					int in_a = 0;
					//p
					cout << "p의 값" << endl;
					std::string sub1 = str_tests.substr(0, 256);
					cout << sub1 << endl;
					p._hex2bn(sub1.c_str());

					//q
					cout << "q의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					q._hex2bn(sub1.c_str());

					//g
					cout << "g의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					g._hex2bn(sub1.c_str());

					//g0
					cout << "g0의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					g0._hex2bn(sub1.c_str());

					//g1
					cout << "g1의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					g1._hex2bn(sub1.c_str());

					//g2
					cout << "g2의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					g2._hex2bn(sub1.c_str());

					//B
					cout << "B의 값" << endl;
					in_a += in_256;
					sub1 = str_tests.substr(in_a, 256);
					cout << sub1 << endl;
					B._hex2bn(sub1.c_str());

					//알파
					cout << "alpa의 값" << endl;
					for (int i = 0; i < 5; i++) {	//큰 db쓸 경우 50000까지 받아야함!

						in_a += in_256;
						sub1 = str_tests.substr(in_a, 256);
						//cout << sub1 << endl;
						arrs_3[i]._hex2bn(sub1.c_str());
					}


					//오메가
					cout << "omega의 값" << endl;
					for (int i = 0; i < 5; i++) {	//큰 db쓸 경우 50000까지 받아야함!

						in_a += in_256;
						sub1 = str_tests.substr(in_a, 256);
						//cout << sub1 << endl;
						arrs_4[i]._hex2bn(sub1.c_str());
					}

					//파이
					cout << "pi의 값" << endl;
					for (int i = 0; i < 3; i++) {

						in_a += in_256;
						sub1 = str_tests.substr(in_a, 256);
						cout << sub1 << endl;
						arr_pi[i]._hex2bn(sub1.c_str());
					}

					Server_Tesk();

					std::cout << "hihi world" << std::endl;


					std::string msg, msg1, msg2, msg3;

					/*
					msg3 = p._bn2hex();
					//SEND THE MESSAGE
					send(clients[0].sock, msg3.c_str(), msg3.size(), 0);
					*/

					cout << "==== S =====" << endl;
					cout << S._bn2hex() << endl;
					cout << "==== beta1 =====" << endl;
					cout << arrs_beta[0]._bn2hex() << endl;
					cout << arrs_beta[1]._bn2hex() << endl;
					cout << arrs_beta[2]._bn2hex() << endl;
					cout << "==== U =====" << endl;
					cout << arrs_U[0]._bn2hex() << endl;
					cout << arrs_U[1]._bn2hex() << endl;
					cout << arrs_U[2]._bn2hex() << endl;
					cout << "==== pi =====" << endl;
					cout << arrs_pi_eq[0]._bn2hex() << endl;
					cout << arrs_pi_eq[1]._bn2hex() << endl;
					cout << arrs_pi_eq[2]._bn2hex() << endl;


					jj = 1;




					for (int i = 0; i < clients.size(); i++) {

						cout << "메시지 보내는중..." << endl;
						cout << "S 보내는 부분" << endl;
						msg = S._bn2hex();
						//msg1 = arrs_pi_eq[0]._bn2hex();
						//msg2 = arrs_pi_eq[1]._bn2hex();
						//msg3 = arrs_pi_eq[2]._bn2hex();
						//SEND THE MESSAGE
						send(clients[i].sock, msg.c_str(), msg.size(), 0);
						cout << S._bn2hex() << endl;
						//send(clients[0].sock, msg1.c_str(), msg1.size(), 0);
						//send(clients[0].sock, msg2.c_str(), msg2.size(), 0);
						//send(clients[0].sock, msg3.c_str(), msg3.size(), 0);
						cout << "베타 보내는 부분" << endl;
						for (int j = 0; j < 5; j++) {	//10만으로 바꾸기
							if (arrs_beta[j] == NULL) break;
							msg = arrs_beta[j]._bn2hex();
							send(clients[i].sock, msg.c_str(), msg.size(), 0);
							cout << arrs_beta[j]._bn2hex() << endl;
						}
						cout << "U보내는 부분" << endl;
						for (int j = 0; j < 5; j++) {	//5만으로 바꾸기
							if (arrs_U[j] == NULL) break;
							msg = arrs_U[j]._bn2hex();
							send(clients[i].sock, msg.c_str(), msg.size(), 0);
							cout << msg << endl;
							cout << arrs_U[j]._bn2hex() << endl;
						}
						cout << "파이 보내는 부분" << endl;
						for (int j = 0; j < 3; j++) {
							if (arrs_pi_eq[j] == NULL) break;
							msg = arrs_pi_eq[j]._bn2hex();
							send(clients[i].sock, msg.c_str(), msg.size(), 0);
							cout << arrs_pi_eq[j]._bn2hex() << endl;
						}

						std::this_thread::sleep_for(std::chrono::seconds(1));
						msg = "hi";

						send(clients[i].sock, msg.c_str(), msg.size(), 0);
						std::this_thread::sleep_for(std::chrono::seconds(1));



					}

					cout << "메시지 다 보냄!" << endl;


				}




			}
			

		}



	});

	//CHECK CONNECTIONS - THREAD 02
	std::thread checker([&clients]() {

		std::string msg, msg1, msg2, msg3;
		while (1) {
			//if (jj == 1) {
				//cout << "메시지 보내는 부분!!" << endl;
				//CYCKLE TROUGH ALL THE CLIENTS
				for (int i = 0; i < clients.size(); i++) {
					//SEND EMPTY MESSAGE TO ALL CLIENTS
					if (send(clients[i].sock, "", 1, 0) < 0) {

						//IF CLIENT FAILS TO RECEIVE THE MESSAGE
						//PRINT OUT MESSAGE THAT THAT CLIENT HAS DISCONNECTED
						std::cout << "Client " << clients[i].client_ip << ":" << i << " Disconnected!" << std::endl;
						//ERASE THE CLIENT FROM THE LIST
						clients.erase(clients.begin() + i);
					}
				}

				//jj = 0;


		}
		
			//WAIT ONE SECOND BEFORE CHECKING CONNECTION AGAIN
			std::this_thread::sleep_for(std::chrono::seconds(1));
		});

	//CONTROLL THE SERVER - MAIN THREAD

	
	std::string msg;
	while (true) {
		std::getline(std::cin, msg);
		if (msg == "stop") {
			break;
		}
	}
	WSACleanup();
	system("pause");
	quick_exit(0);
	

	/////////////////////////////////////////////////














}