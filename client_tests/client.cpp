#include<iostream>
#include<stdio.h>
#include<string.h>
#include<WS2tcpip.h>
#include<sstream>
#include<thread>
#include <mysql.h>
#include <stdlib.h>
#include "typeinfo"
#include "openssl/applink.c"
#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "libmysql.lib")
#include <cstdio>
#define _CRT_SECURE_NO_WARNINGS
#include "crypt.h"
#include <cassert>
#include <cstring>
#include <openssl/sha.h>
#include <iomanip>
#include<string>
#define NUMBER_s = 500000

//#include "KISA_SHA256.h"
#pragma warning (disable:4996)
//#pragma comment("libcrypto-1_1-x64.dll")

_openssl_BN r, s, t, u, v, w, tempt, tempt2, I, A, B, X, H, g0, r0, r1, e;
_openssl_BN ALPAi_1, OMEGAi_1, ALPA_OMEGA, y, h, r_1;
_openssl_BN Ai, Bi, ALPAi, OMEGAi, ri, g1, g2, g0_s, g1_s, g2_s, arrs_A_test;
_openssl_BN q, p, g, ss = 2;

_openssl_BN arrs[50000];	//DB값 들어오는 부분
_openssl_BN arrs_A[50000];	//Ai부분
_openssl_BN arrs_B[50000];	//빵꾸내서 해쉬해서 곱해주는 부분 => Bi
_openssl_BN arrs_3[50000];	//추가로 더 달아서 테스트 방지하는부분 => 알파i
_openssl_BN arrs_4[50000];	//오메가i부분
_openssl_BN random_r[50000];

//서버로부터 받아들여오는 값
_openssl_BN S, arrs_beta[100000], arrs_U[100000], arrs_pi_s[3];



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
_openssl_BN arr_pi[3];

_openssl_BN *TwoProver(_openssl_BN p, _openssl_BN g0, _openssl_BN g1, _openssl_BN q, _openssl_BN x0, _openssl_BN x1, _openssl_BN y) {
	_openssl_BN totals, BETA, Tr0, Tr1, Tg0, Tg1, e, z0, z1, e_test;
	std::string str1, str2, str3, str4;
	
	//BETA
	Tr0._randomInplace(q);
	Tr1._randomInplace(q);
	Tg0 = g0._exp(Tr0, p);
	Tg1 = g1._exp(Tr1, p);
	BETA = Tg0._mul(Tg1, p);

	//p, y, BETA 합치기

	str1 = p._bn2hex();
	str2 = y._bn2hex();
	str3 = BETA._bn2hex();
	str4 = str1 + str2 + str3;

	std::cout << "p, y, BETA 영접시키기" << std::endl;
	std::cout << "p의 값" << std::endl;
	std::cout << str1 << std::endl;
	std::cout << "y의 값" << std::endl;
	std::cout << str2 << std::endl;
	std::cout << "BETA의 값" << std::endl;
	std::cout << str3 << std::endl;
	std::cout << "영접된 값" << std::endl;
	std::cout << str4 << std::endl;
	/*
	SHA256_CTX c;
	unsigned char m[SHA256_DIGEST_LENGTH];

	unsigned char *md;
	*/
	//SHA256("123", 256, md);
	str4 = sha256(str4);
	const char *cstr = str4.c_str();
	e._hex2bn(cstr);
	std::cout << e._bn2hex() << std::endl;

	//compute z0 = Tr0 - e * x0 (mod q)
	e_test = e._mul(x0, q);
	z0 = Tr0._sub(e_test, q);

	//compute z1 = Tr0 - e * x1 (mod q)
	e_test = e._mul(x1, q);
	z1 = Tr1._sub(e_test, q);

	arr_pi[0] = BETA;
	arr_pi[1] = z0;
	arr_pi[2] = z1;

	std::cout << "TwoProver함수 처리 전 파이부분" << std::endl;
	std::cout << arr_pi[0]._bn2hex() << std::endl;
	std::cout << arr_pi[1]._bn2hex() << std::endl;
	std::cout << arr_pi[2]._bn2hex() << std::endl;

	printf("///////////////////\n");

	return arr_pi;
}

std::string str1, str2, str3, str4, str5, str6;
_openssl_BN v0, v1, eq_tmp, eq_tmp2;

_openssl_BN EqualVerifer(_openssl_BN p, _openssl_BN g0, _openssl_BN g1, _openssl_BN q, _openssl_BN y0, _openssl_BN y1) {
	str1 = p._bn2hex();
	str2 = y0._bn2hex();
	str3 = y1._bn2hex();
	str4 = arrs_pi_s[0]._bn2hex();	//beta0, pi
	str5 = arrs_pi_s[1]._bn2hex();	//beta1, pi
	str6 = str1 + str2 + str3 + str4 + str5;
	str6 = sha256(str6);
	const char *cstr = str6.c_str();
	e._hex2bn(cstr);

	eq_tmp = g0._exp(arrs_pi_s[2], p);	//arrs_pi_s[2] = z
	eq_tmp2 = y0._exp(e, p);
	v0 = eq_tmp._mul(eq_tmp2, p);
	eq_tmp = g1._exp(arrs_pi_s[2], p);
	eq_tmp2 = y1._exp(e, p);
	v1 = eq_tmp._mul(eq_tmp2, p);

	if (arrs_pi_s[0] == v0 && arrs_pi_s[1] == v1) {
		std::cout << "성공입니당" << std::endl;
		return 1;
	}
	else {
		std::cout << "아닙니당" << std::endl;
		return 0;
	}


}
void Client_Tesk() {
	std::cout << "Let's start this function" << std::endl;



	
	EqualVerifer(p, g1, arrs_3[0], q, S, arrs_beta[0]);
	_openssl_BN temped, arr_k[50000], arr_C[50000], results_I[50000];

	


	// Line 11 ~ 12
	for (int i = 0; i < 50000; i++) {	//50000까지로 변경해야함 
		temped = S._inv(p);
		temped = S._exp(random_r[i], p);
		arr_k[i] = arrs_beta[i]._mul(temped, p);

		str1 = arr_k[i]._bn2hex();
		str2 = arrs_A[i]._bn2hex();
		str3 = arrs[i]._bn2hex();
		str4 = str1 + str2 + str3;
		str4 = sha256(str4);
		const char *cstr = str4.c_str();
		arr_C[i]._hex2bn(cstr);
	}

	// Line 13 ~ 14
	for (int i = 0; i <  50000; i++) {	//50000까지로 변경해야함
		for (int j = 0; j < 100000; j++) {	//100000까지로 변경해야함
			if (arr_C[i] == arrs_U[j]) {
				results_I[i] = arrs[i];
				std::cout << results_I[i]._bn2hex() << std::endl;
			}
		}
	}
	

}





int qstate;
int ab[1001];
int main(int argc, char** argv) {
	using std::cout;
	using std::endl;

	/*
	_openssl_BN hello = 11, hihi = 5, world = 3;
	world._expInplace(hihi, hello);	//g^q
	cout << world._bn2hex() << endl;
	world._add(world, hello);
	cout << world._bn2hex() << endl;
	*/

	///< generate a prime of lenght lambda
	std::cout << "3. ## Prime generation ##" << std::endl;



	unsigned char bytes[1000] = { 0 };
	_openssl_BN a, b(100), c = 1;
	int len = 0, lambda = 1023, count = 0;

	
	q._randomInplace(lambda);	//소수 q를 뽑는다.
	r._randomInplace(2000);

	





	
	while (true) {
		if (q._isPrime()) {
			

			v = q;
			v._mulInplace(ss, r);	//2*q

			w = v._add(c, r);	//2*q +1


			cout << "wait.." << endl;
			
			if (w._isPrime()) break;	//p가 소수라면 종료
				
				
		}
		q._randomInplace(lambda);
	}
	p = w;
	cout << "/////////" << endl;
	cout << q._bn2hex() << endl;	//q값
	cout << "/////////" << endl;
	cout << p._bn2hex() << endl;	//p값
	cout << "==============" << endl;
	









	//g 찾기
	while (true) {

		if (g != 0 && g != c) {	//c == 1
			tempt = g;
			tempt._expInplace(ss, p);	//g^2, (ss == 2)
			if (tempt != c) {	//c == 1
				tempt2 = g;
				tempt2._expInplace(q, p);	//g^q
				cout << "wait.. g.." << endl;

				if (tempt2 == c) {	//c == 1

					break;
				}
			}
		}
		g._randomInplace(p);	//p범위 내에 있는 랜덤수 뽑기
	}

	cout << "/////////" << endl;
	cout << g._bn2hex() << endl;	//g값

	cout << "==============" << endl;
	

	///////////////////////////////////////
	/* 1번째 줄 */

	printf("MySQL client Version : %s\n", mysql_get_client_info());

	MYSQL* conn;
	MYSQL_ROW row;
	MYSQL_RES *res;
	conn = mysql_init(0);

	conn = mysql_real_connect(conn, "localhost", "root", "wndkdi123", "_privatesetx", 3308, NULL, 0);

	_openssl_BN H_1, NUM = 1, H_test;
	char* tests;
	std::cout << "&&** row의 수" << std::endl;
	res = mysql_store_result(conn);
	std::cout << int(conn) << std::endl;
	std::cout << int(res) << std::endl;



	if (conn) {
		puts("Successful connection to database!");

		std::string query = "SELECT * FROM _privatesetx";
		const char* Q = query.c_str();
		qstate = mysql_query(conn, Q);
		if (!qstate) {
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				printf("ID: %s, Name: %s, Value: %s\n", row[0], row[1], row[2]);

				//첫번째 요소를 가지고,,
				char* tests_1 = row[0];	//tests_1 -> x
				//printf("%s\n", tests_1);

				//tests_1을 string에서 _openssl_BN으로 변환. 다른 변수를 만들어서 넣어준다.

				// A에 H1(X) 들을 넣고 곱해서 mod p
				H_test._hex2bn(tests_1);
				H_1 = g._exp(H_test, p);	//H_1 = g^x (mod p)

				NUM = NUM._mul(H_1, p);		//들어온것들을 곱해준다.
				
			}
		}
		else {
			std::cout << "Query failed: " << mysql_error(conn) << std::endl;
		}
		printf("the end!! \n");
		




	}
	else {
		puts("Connection to database has falied!");
	}

	/*
	//할당된 메모리 해제
	mysql_free_result(res);
	mysql_close(conn);
	*/


	/////////////////////////////////////////
	

	conn = mysql_init(0);

	conn = mysql_real_connect(conn, "localhost", "root", "wndkdi123", "_privatesetx", 3308, NULL, 0);


	//Line 2
	//H = g._exp(X, p);	//H = g^x (mod p)

	int el = 0;

	
	_openssl_BN ran_r;
	ran_r._randomInplace(q);
	g0 = g._exp(ran_r, p);
	//g0_s = g0._exp(r, p);
	B = NUM._mul(g0, p);	//B = NUM * g0 (mod p)	<NUM == A>

	
	int length = int(row);
	//Line 3~5
	if (conn) {
		//puts("Successful connection to database!");

		std::string query = "SELECT * FROM _privatesetx";
		const char* Q = query.c_str();
		qstate = mysql_query(conn, Q);
		if (!qstate) {
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				char* tests_1 = row[0];	//tests_1 -> x

				H_test._hex2bn(tests_1);	//H_test는 x시리즈이다. (xi이다.)
				arrs[el] = H_test;
				//printf("db내용\n");
				//cout << el << endl;
				//cout << arrs[el]._bn2hex() << endl;

				el++;
			}
		}
		printf("the end!! \n");
	}
	



	cout << "곱하고 빵꾸내는 부분" << endl;
	for (int i = 0; i < 50000; i++) {
		
		arrs_A[i] = g._exp(arrs[i], p);	//Ai = g^x (mod p) <해쉬처리>

		if (arrs[i] == NULL) break;
		arrs_B[i] = 1;	//Bi부분

		arrs_A_test = arrs_A[i]._inv(p);
		arrs_B[i] = NUM._mul(arrs_A_test, p);

		//Bi 빵꾸내는부분
		cout << "Bi" << endl;
		cout << arrs_B[i]._bn2hex() << endl;

		//알파i (arrs_3)
		//랜덤값 r을 뽑아준다.	(g1을 위하여)
		random_r[i]._randomInplace(q);
		
		//tests_g._randomInplace(q);
		g1 = g._exp(random_r[i], p);
		arrs_3[i] = arrs_A[i]._mul(g1, p);	//Ai * gi
		cout << "알파" << endl;
		cout << arrs_3[i]._bn2hex() << endl;

		//오메가i부분 (arrs_4)
		//랜덤값 r을 뽑아준다.	(g2를 위하여)
		g2 = g._exp(random_r[i], p);
		arrs_4[i] = arrs_B[i]._mul(g2, p);	//Bi * g2
		cout << "오메가" << endl;
		cout << arrs_4[i]._bn2hex() << endl;

	}


	std::cout << "**====**====**====**" << std::endl;

	_openssl_BN x0, x1, g_0, g_1;
	
	_openssl_BN alpa1, omega1;
	alpa1 = arrs_3[0]._inv(p);
	omega1 = arrs_4[0]._inv(p);
	alpa1 = alpa1._mul(omega1, p);
	y = B._mul(alpa1, p);

	h = g1._mul(g2, p);	//h = (g1 * g2) (mod p)

	_openssl_BN _r;
	_r = random_r[0]._mul(-1, p);
	

	_openssl_BN *ptr_pi = TwoProver(p, g0, h, q, r, _r, y);

	cout << "TwoProver함수 처리 후 파이부분" << endl;
	cout << arr_pi[0]._bn2hex() << endl;
	cout << arr_pi[1]._bn2hex() << endl;
	cout << arr_pi[2]._bn2hex() << endl;

	


	///////////////////////////////////
	//INITIALIZE WINSOCK
	WSADATA some_kind_of_data;
	WSAStartup(MAKEWORD(2, 2), &some_kind_of_data);

	//CREATE CONNECTION SOCKET
	sockaddr_in connect_adress;
	connect_adress.sin_family = AF_INET;
	connect_adress.sin_port = htons(666);
	inet_pton(AF_INET, "127.0.0.1", &connect_adress.sin_addr);
	SOCKET connection_socket = socket(AF_INET, SOCK_STREAM, 0);

	//CONNECT TO SERVER - THREAD 01
	bool is_connected = false;

	std::thread connector([=,&connection_socket, &connect_adress, &is_connected]() {
		while (true) {
			//TRY SENDING MESSAGE TO SEE IF ITS CONNECTED
			if (send(connection_socket, "", 1, 0) == SOCKET_ERROR) {
				//IF NOT CONNECTED :
				is_connected = false;
				//RESET THE CONNECTION SOCKET
				connection_socket = socket(AF_INET, SOCK_STREAM, 0);
				//TRY TO CONNECT TO THE SERVER, IN A LOOP
				while (true) {
					std::cout << "Trying to connect to server...\n";
					if (connect(connection_socket, (sockaddr*)&connect_adress, sizeof(connect_adress)) != SOCKET_ERROR) {
						//IF IT CONNECTS TO THE SERVER
						std::cout << "Connected to server!\n";
						is_connected = true;
						//GOES BACK TO SENDING MESSAGES TO SEE IF ITS STILL CONNECTED
						break;
					}
				}
			}
			//SLEEP FOR ONE SECOND
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}});











	//SEND A MESSAGES - MAIN THREAD
	std::string msg;
	std::string msg_1;
	std::string msg_2;
	std::string msg_3;
	std::string msg_g;
	std::string msg_p;
	std::string msg_q;
	std::string msg_g0;
	std::string msg_g1;
	std::string msg_g2;


	msg_p = p._bn2hex();
	msg_q = q._bn2hex();
	msg_g = g._bn2hex();
	msg_g0 = g0._bn2hex();
	msg_g1 = g1._bn2hex();
	msg_g2 = g2._bn2hex();

	int testsss2[3] = { 5,6,7 };

	int counts = 0;
	int couns_2 = 1;
	int lss = 1;

	while (true) {
		///////
		if (is_connected == true) {


			if (conn) {
				while (couns_2) {
					send(connection_socket, msg_p.c_str(), msg_p.size(), 0);	//p값 서버로 전달
					cout << msg_p.c_str() << endl;
					send(connection_socket, msg_q.c_str(), msg_q.size(), 0);	//q값 서버로 전달
					cout << msg_q.c_str() << endl;
					send(connection_socket, msg_g.c_str(), msg_g.size(), 0);	//g값 서버로 전달
					cout << msg_g.c_str() << endl;
					send(connection_socket, msg_g0.c_str(), msg_g0.size(), 0);	//g0값 서버로 전달
					cout << msg_g0.c_str() << endl;
					send(connection_socket, msg_g1.c_str(), msg_g1.size(), 0);	//g1값 서버로 전달
					cout << msg_g1.c_str() << endl;
					send(connection_socket, msg_g2.c_str(), msg_g2.size(), 0);	//g2값 서버로 전달
					cout << msg_g2.c_str() << endl;


					cout << "전송" << endl;


					std::string test_send;

					//B보내는 부분
					//cout << "B 보내는 부분" << endl;
					test_send = B._bn2hex();
					send(connection_socket, test_send.c_str(), test_send.size() , 0);	//g값 서버로 전달
					//cout << test_send.c_str() << endl;
					//std::this_thread::sleep_for(std::chrono::seconds(1));

					//알파 보내는 부분
					//알파i (arrs_3)
					//cout << "알파 보내는 부분" << endl;
					for (int i = 0; i < 50000; i++) {
						if (arrs_3[i] == NULL) break;
						test_send = arrs_3[i]._bn2hex();
						//cout << test_send.c_str() << endl;
						send(connection_socket, test_send.c_str(), test_send.size() , 0);	//g값 서버로 전달
						//std::this_thread::sleep_for(std::chrono::seconds(1));
					}

					//오메가 보내는 부분
					//오메가i (arrs_4)
					//cout << "오메가 보내는 부분" << endl;
					for (int i = 0; i < 50000; i++) {
						if (arrs_4[i] == NULL) break;
						test_send = arrs_4[i]._bn2hex();
						//cout << test_send.c_str() << endl;
						send(connection_socket, test_send.c_str(), test_send.size() , 0);	//g값 서버로 전달
						//std::this_thread::sleep_for(std::chrono::seconds(1));
					}

					//파이c보내는 부분
					//cout << "파이c보내는 부분" << endl;
					for (int i = 0; i < 3; i++) {
						test_send = arr_pi[i]._bn2hex();
						//cout << test_send.c_str() << endl;
						send(connection_socket, test_send.c_str(), test_send.size() , 0);	//g값 서버로 전달
						//std::this_thread::sleep_for(std::chrono::seconds(1));
					}
						
					//std::this_thread::sleep_for(std::chrono::seconds(1));
					test_send = "hi";

					send(connection_socket, test_send.c_str(), test_send.size(), 0);
					//std::this_thread::sleep_for(std::chrono::seconds(1));


					


					//////////////////////////////////////////////


					char buffer[1024];
					char* temp;

					std::string str_tests;
					int S_counts = 1;
					std::string hi = "hi";
					int jj = 1;

					while (jj == 1) {
						//RESET BUFFER EVERY TIME
						memset(buffer, 0, sizeof(buffer));
						//IF MESSAGE RECEIVED IS LONGER THEN ONE BYTE, PRINT IT OUT
						if (recv(connection_socket, buffer, sizeof(buffer), 0) >= 1) {
							//cout << "hello world" << endl;

							temp = strdup(buffer);
							str_tests = str_tests + temp;
							//cout << temp << endl;

							if (str_tests.find(hi) != std::string::npos) {
								cout << "i found!!" << endl;
								jj = 0;
							}
						}
					}

					if (jj == 0) {
						cout << "============" << endl;
						cout << str_tests << endl;


						int in_256 = 256;
						int in_64 = 64;
						int in_a = 0;

						//S받아오는 부분
						cout << "S 받아온 부분" << endl;
						std::string sub1 = str_tests.substr(0, 256);
						cout << sub1 << endl;
						S._hex2bn(sub1.c_str());

						//beta시리즈 받아오는 부분
						cout << "beta시리즈 받아온 부분" << endl;
						for (int i = 0; i < 100000; i++) {	//큰 db쓸 경우 100000까지 받아야함!

							in_a += in_256;
							sub1 = str_tests.substr(in_a, 256);
							cout << sub1 << endl;
							arrs_beta[i]._hex2bn(sub1.c_str());
						}

						//U시리즈 받아오는 부분
						cout << "U시리즈 받아온 부분" << endl;
						for (int i = 0; i < 50000; i++) {	//큰 db쓸 경우 50000까지 받아야함!

							in_a += in_64;
							sub1 = str_tests.substr(in_a, 64);
							cout << sub1 << endl;
							arrs_U[i]._hex2bn(sub1.c_str());
						}

						//파이 받아오는 부분
						cout << "pi시리즈 받아온 부분" << endl;
						for (int i = 0; i < 3; i++) {

							in_a += in_256;
							sub1 = str_tests.substr(in_a, 256);
							cout << sub1 << endl;
							arrs_pi_s[i]._hex2bn(sub1.c_str());
						}

						cout << "go to client_tesk function" << endl;

						Client_Tesk();
						lss = 0;




						couns_2 = 0;
					}
					
				}
			}

			////////



			//ASK USER TO TYPE THE MESSAGE
			std::getline(std::cin, msg);
			//SEND THE MESSAGE
			if (send(connection_socket, msg.c_str(), msg.size() + 1, 0) <= 0)
				//IF IT FAILS TO SEND THE MESSAGE
				std::cout << "Failed to send the message...\n";

		}
		//SLEEP FOR 1S IF SOCKET IS NOT CONNECTED
		//else std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	

	//RECEIVE MESSAGES FROM SERVER - THREAD 02
	std::thread receiver([=, &connection_socket, &is_connected]() {
		//STORE RECEIVED MESSAGE INSIDE THIS BUFFER
		char buffer[1024];
		char* temp;

		std::string str_tests;
		int S_counts = 1;
		std::string hi = "hi";
		int jj = 1;

		while (true) {
			if (is_connected == true) {
				//RESET BUFFER EVERY TIME
				memset(buffer, 0, sizeof(buffer));
				//IF MESSAGE RECEIVED IS LONGER THEN ONE BYTE, PRINT IT OUT
				if (recv(connection_socket, buffer, sizeof(buffer), 0) > 1)
					std::cout << buffer << std::endl;
			}
			//SLEEP FOR 1S IF NOT CONNECTED
			else std::this_thread::sleep_for(std::chrono::seconds(1));
		}});



	/*
	closesocket(connection_socket);
	WSACleanup();
	quick_exit(0);
	*/


	return 0;
}