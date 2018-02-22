/*
 * main2.cc
 *
 *  Created on: Aug 15, 2013
 *      Author: rick
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <PBC/PBC.h>
#include <vector>
#include "systemparam.h"
#include "io.h"
#include "lagrange.h"

void openFile(char *filePath, char **buffer, size_t *size){


	FILE *file;
	long lSize;


	file = fopen(filePath, "r");

	fseek(file, 0, SEEK_END);
	lSize = ftell(file);
	rewind(file);
	// allocate memory to contain the whole file:
	*buffer = (char*) (malloc(sizeof(char) * lSize));
	if (*buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}
	// copy the file into the share_buffer:
	*size = fread(*buffer, 1, lSize, file);
	//fgets(*buffer, lSize, file);
//	if (*size != lSize) {
//		fputs("Reading error", stderr);
//		exit(3);
//	}
	/* the whole file is now loaded in the memory share_buffer. */
	// terminate
	fclose(file);

}

G1 openPublicKey (char *filePath, const Pairing& e){

	char *buffer;
	size_t size;

	openFile(filePath, &buffer, &size);

	//char *tok;

	//tok = strtok(buffer, ":");
	//if(tok != NULL)
	//		tok = strtok(NULL, ":");

	return G1(e, (unsigned char *)buffer, size, false, 10);

}

Zr openShare(char *filePath, const Pairing& e){

	char *buffer;
	size_t size;

	openFile(filePath, &buffer, &size);

	char *tok;

	tok = strtok(buffer, ": \n");
	//if(tok != NULL)
	//	tok = strtok(NULL, ":");

	return Zr (e, (unsigned char *)tok, size, 10);

}

int main(){

	SystemParam sysparam ("pairing.param", "system.param");

	const Pairing& e = sysparam.get_Pairing();

	Zr indice1(e, (long)1);
	indice1.dump(stderr, "indice 1", 10);
	Zr indice2(e, (long)2);
	indice2.dump(stderr, "indice 2", 10);
	Zr indice3(e, (long)3);
	indice3.dump(stderr, "indice 3", 10);
	Zr indice4(e, (long)4);
	indice4.dump(stderr, "indice 4", 10);
	Zr zr_share1, zr_share2, zr_share3, zr_share4;
	G1 g1_publicKey;

	G1 pub1, pub2, pub3, pub4;

	char c_share1[14] = "shares/priv1";
	char c_share2[14] = "shares/priv2";
	char c_share3[14] = "shares/priv3";
	char c_share4[14] = "shares/priv4";
	char c_pub1[14] = "shares/pub1";
	char c_pub2[14] = "shares/pub2";
	char c_pub3[14] = "shares/pub3";
	char c_pub4[14] = "shares/pub4";

	zr_share1 = openShare(c_share1, e);
	zr_share1.dump(stderr, "zr_share1", 10);
	zr_share2 = openShare(c_share2, e);
	zr_share2.dump(stderr, "zr_share2", 10);
	zr_share3 = openShare(c_share3, e);
	zr_share3.dump(stderr, "zr_share3", 10);
	zr_share4 = openShare(c_share4, e);
	zr_share4.dump(stderr, "zr_share4", 10);

	pub1 = openPublicKey(c_pub1, e);
	pub1.dump(stderr, "pub1: ", 10);
	pub2 = openPublicKey(c_pub2, e);
	pub2.dump(stderr, "pub2: ", 10);
	pub3 = openPublicKey(c_pub3, e);
	pub3.dump(stderr, "pub3: ", 10);
	pub4 = openPublicKey(c_pub4, e);
	pub4.dump(stderr, "pub4: ", 10);

	g1_publicKey = openPublicKey("pubsys1", e);
	g1_publicKey.dump(stderr, "public file", 10);

	std::string id = "rick";

	G1 msgHashG1, g1_share1, g1_share2, g1_share3, g1_share4;
	hash_msg(msgHashG1, id,e);

	g1_share1 = msgHashG1^zr_share1;
	g1_share1.dump(stderr, "g1_share1", 10);
	g1_share2 = msgHashG1^zr_share2;
	g1_share2.dump(stderr, "g1_share2", 10);
	g1_share3 = msgHashG1^zr_share3;
	g1_share3.dump(stderr, "g1_share3", 10);
	g1_share4 = msgHashG1^zr_share4;
	g1_share4.dump(stderr, "g1_share4", 10);

	sysparam.get_U().dump(stderr, "U: ", 10);
	msgHashG1.dump(stderr, "HashG1: ", 10);
	cout << "\n" <<endl;
	e(g1_share1, sysparam.get_U()).dump(stderr, "e1: ", 10);
	cout << "\n" <<endl;
	e(msgHashG1, pub1).dump(stderr, "e2: ", 10);
	cout << "\n" <<endl;

	if (e(g1_share1, sysparam.get_U()) == e(pub1, msgHashG1)) {
			cerr << "\n*** CORRECT!\n\n";
		} else {
			cerr << "\n*** DIFFERENT!\n\n";
			//Send a Wrong Signatures Message
		}

	if (e(sysparam.get_U(), g1_share2) == e(pub2, msgHashG1)) {
			cerr << "\n*** CORRECT!\n\n";
		} else {
			cerr << "\n*** DIFFERENT!\n\n";
			//Send a Wrong Signatures Message
		}

	if (e(sysparam.get_U(), g1_share3) == e(pub3, msgHashG1)) {
			cerr << "\n*** CORRECT!\n\n";
		} else {
			cerr << "\n*** DIFFERENT!\n\n";
			//Send a Wrong Signatures Message
		}

	if (e(sysparam.get_U(), g1_share4) == e(pub4, msgHashG1)) {
			cerr << "\n*** CORRECT!\n\n";
		} else {
			cerr << "\n*** DIFFERENT!\n\n";
			//Send a Wrong Signatures Message
		}

	vector <Zr> indices; vector <G1> shares;

	indices.push_back(Zr(e,(signed long)1));
	indices.push_back(Zr(e,(signed long)2));
	indices.push_back(Zr(e,(signed long)3));
	indices.push_back(Zr(e,(signed long)4));

	shares.push_back(g1_share1);
	shares.push_back(g1_share2);
	shares.push_back(g1_share3);
	shares.push_back(g1_share4);

	Zr alpha(e,(long)0);
	vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
	G1 did = lagrange_apply(coeffs, shares);

	did.dump(stderr, "TempSignature", 10);
	g1_publicKey.dump(stderr, "PublicKey: ", 10);
	msgHashG1.dump(stderr, "Hash ", 10);

	if (e(sysparam.get_U(), did) == e(g1_publicKey, msgHashG1)) {
		cerr << "\n*** CORRECT!\n\n";
	} else {
		cerr << "\n*** DIFFERENT!\n\n";
		//Send a Wrong Signatures Message
	}

	//******************************* Cifrar  ************************************ //
	GT gid = e(g1_publicKey, msgHashG1);
	Zr r (e, true);
	GT gidr =gid^r;

	unsigned char *u_gidr;
	int size_gidr;

	size_gidr = element_length_in_bytes(*(element_t*)&gidr.getElement());
	u_gidr = (unsigned char *)calloc( size_gidr, sizeof(unsigned char));
	element_to_bytes(u_gidr, *(element_t*)&gidr.getElement());

	unsigned char hash_gidr[SHA_DIGEST_LENGTH]={0};
	SHA1(u_gidr, size_gidr, hash_gidr);

	char *texto_claro = "Texto sigiloso que deve ser cifrado e então decifrado";
	printf("Texto em claro: %s \n", texto_claro);
	int data_len = strlen(texto_claro);

	unsigned char *encrypted_data;
	encrypted_data = (unsigned char *)calloc( data_len, sizeof(unsigned char));

	int i;
	for(i = 0; i < data_len ; i++)
	{
		encrypted_data[i] = texto_claro[i]^hash_gidr[i % SHA_DIGEST_LENGTH];
	}

	G1 U = sysparam.get_U()^r;

	//******************************* Decifrar  ************************************ //

	GT xt = e(did, U);

	unsigned char *u_xt;
	int size_xt;

	size_xt = element_length_in_bytes(*(element_t*)&xt.getElement());
	u_xt = (unsigned char *)calloc( size_xt, sizeof(unsigned char));
	element_to_bytes(u_xt, *(element_t*)&xt.getElement());

	unsigned char hash_xt[SHA_DIGEST_LENGTH]={0};
	SHA1(u_xt, size_xt, hash_xt);

	unsigned char *decrypted_data;
	decrypted_data = (unsigned char *)calloc( data_len, sizeof(unsigned char));

	for(i = 0; i < data_len; i++)
	{
		decrypted_data[i] = encrypted_data[i]^ hash_xt[i % SHA_DIGEST_LENGTH];
	}

	printf("Texto decifrado: %s \n", decrypted_data);

	return 0;
}
