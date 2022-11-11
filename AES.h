#pragma once

// Class of the AES containg all the things and attributes needed
class AES
{

	const unsigned char s_box[16][16]; // the s box for the substitution
	const unsigned char s_box_inverse[16][16]; // the s box inverse
	const unsigned char roundConstants[10]; //the round constants

	const string key;

	string* roundkeys; //the keys that will be used in the rounds

public:
	// constructor with initalizer list for AES
	AES(const string keyEntered);

	// will perform the key expansions and will store the round keys accordingly
	void performKeyExpansion();

	//will see whole string in the s-box
	string substituteWholestring(string toSubstitute);

	//find the gw
	string findGW(string w, const short round);

	// rotateleft with the given number of shifts and returned the shifted 
	// will use for right also by maping the figures
	string rotLeft(string shiftIt, const int shifts);

	// will see what's in the sbox
	unsigned char fromSbox(unsigned char toConvert);

	// will see what's in the sbox inverse
	unsigned char fromSbox_inverse(unsigned char toConvert);

	// will substitute from the s box and will cahne given array with the substituted one
	void byteSubstitute(string& s);

	// adding the bytes 
	unsigned char addBytes(const unsigned char byte1, const unsigned char byte2);

	//adding the round constants
	string addRoundConstant(string addIn, const short round);

	//xor the two strings
	string addStrings(string a, string b);

	// always will be 4*4 because always 128 bits will be used
	// will substitue the given matrix with s box
	void Byte_Substitution_Encrypt(unsigned char substituteMe[4][4]);
	// for decryption
	void Byte_Substitution_Decrypt(unsigned char substituteMe[4][4]);

	//shifting the rows of the state matrix
	void Row_Shifting_Encryption(unsigned char shiftMe[4][4]);

	//shifting the rows of the state matrix --- inverse
	void Row_Shifting_Decryption(unsigned char shiftMe[4][4]);

	void print(unsigned char a[4][4]);

	//mix the columns --- multiplication
	void Mix_Columns_Encryption(unsigned char muliplywith[4][4]);

	//inverse
	void Mix_Columns_Decryption(unsigned char muliplywith[4][4]);

	//for adding the round key to the matrix
	void Add_roundKey(unsigned char currentStateMatrix[4][4], const int round);

	// for debugging , printing chharacters to hex
	void printHex(string s);

	// will intilazie the given 2d column wise
	void initalizeMe_columnwise(unsigned char matrix[4][4], string withThis);

	// will xor the two matrices and result will be in the matrix1
	void addThesetwo_Matrices(unsigned char matrix1[4][4], unsigned char matrix2[4][4]);

	//will return string from the coulmn wise matrx
	string revertColumnwise_matrix(unsigned char matrix[4][4]);
	// the whole encryption process
	string encryption(string plainText);

	//performing decryption
	string decryption(string cipherText);

	// the destructor
	~AES();

};
