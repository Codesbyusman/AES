#include <iostream>
#include <string.h>
#include <cstdlib>
#include <string>
#include <fstream>

using namespace std;

#include "AES.h"

int main()
{

	char option = '0';

	cout << "\n\t\t --------------------------------------------------------------------------" << endl;

	cout << "\n\t\t :::::::::::::::::::: [+] Advance Encryption Standard [+] :::::::::::::::::" << endl;

	cout << "\n\t\t --------------------------------------------------------------------------" << endl << endl;

	string input = "";
	string key = "";

	string file1 = "";
	string file2 = "";

filesAgain:

	file1 = ""; // the one having text
	file2 = "";  //key

	input = "";
	key = "";

	cout << "\n\t Enter the file name to encrypt/decrypt  : ";
	cin >> file1;
	
	//the one having text
	fstream File(file1, ios::in);

	// if opened
	if (File)
	{
		string line = "";
		//till the end of file
		while (!File.eof())
		{
			getline(File, line);
			input += line;
		}
		File.close(); //done close the file

		if (input.length() != 16)
		{
			cout << "\n\t ::::::::: AES Version 1.0 Only supports exact 128 bit --- 16 bytes ::::::::::::::::" << endl;
			cout << "\n\t ::::::::::::::::::: Kindly wait for Version 1.2; Sorry :( :::::::::::::::::::::::::" << endl;
			return 0;
		}
	}
	else
	{
		cout << "\n\t\t ::::::: No such file exist --- make sure in same folder ::::::::::" << endl;
		return 0;
	}


	cout << "\n\t Enter the file name containing key  : ";
	cin >> file2;

	//the one having text
	File.open(file2, ios::in);

	// if opened
	if (File)
	{
		string line = "";
		//till the end of file
		while (!File.eof())
		{
			getline(File, line);
			key += line;
		}
		File.close(); //done close the file

		if (key.length() != 32)
		{
			cout << "\n\t ::::::::: AES 256 only 256 bit key , 32 bytes ::::::::::::::::" << endl;
			return 0;
		}
		
	}
	else
	{
		cout << "\n\t\t ::::::: No such file exist --- make sure in same folder ::::::::::" << endl;
		return 0;
	}

	AES aes(key);
	string encrypt = "";
	string decrypt = "";

	encrypt = aes.encryption(input);
	decrypt = aes.decryption(encrypt);

again:

	cout << "\n\t\t :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" << endl << endl;

	cout << "\n\t\t\t\t 1 to see Encryption \n\t\t\t\t 2 to see Decryption \n\t\t\t\t 3 to see Encryption and Decryption with Hex \n\t\t\t\t 4 for changing files \n\t\t\t\t Any other character to exit" << endl;
	cout << "\n\t\t\t\t Enter the desire option : ";
	cin >> option;

	cout << "\n\t\t :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" << endl;
	

	switch (option)
	{
		//encryption
	case '1':

		cout << "\n\t Encrypted : " << encrypt << endl;
		goto again;
		//decryption
	case '2':
		cout << "\n\t Decrypted : " << decrypt << endl;
		goto again;

		//encryption/decryption cli
	case '3':

		cout << "\n\t\t\t ::::::: String Printing :::::::" << endl;

		cout << " \n Original  Text : " << input << endl;
		cout << " \n Encrypted Text : " << encrypt << endl;
		cout << " \n Decrypted Text : " << decrypt << endl;

		cout << "\n\t\t\t ::::::: Hex Printing :::::::" << endl;

		cout << " \n Original  Hex : ";
		aes.printHex(input);
		cout << " \n Encrypted Hex : ";
		aes.printHex(encrypt);
		cout << " \n Decrypted Hex : ";
		aes.printHex(decrypt);

		goto again;
	case '4':
		goto filesAgain;
		break;
	default:
		cout << "\n\t\t\t\t :::::::: Exiting :| :::::::::" << endl;
	}

	return 0;
}


// ------------------------------------------------------------------
// ------------------------- Class Functions ------------------------
// ------------------------------------------------------------------

// constructor with initalizer list for AES
AES::AES(const string keyEntered) :
	s_box{
		{0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76},
		{0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0},
		{0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15},
		{0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75},
		{0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84},
		{0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf},
		{0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8},
		{0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2},
		{0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73},
		{0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb},
		{0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79},
		{0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08},
		{0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a},
		{0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e},
		{0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf},
		{0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16}
},
s_box_inverse{
	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
},
roundConstants{
	0x01, 0x02 , 0x04, 0x08, 0x10 , 0x20, 0x40 , 0x80 , 0x1b, 0x36
},
key(keyEntered)
{

	roundkeys = new string[14]; //without 0 round that is actual key

	// will perform the key expansions and will store the round keys accordingly
	performKeyExpansion();
};

// will perform the key expansions and will store the round keys accordingly
void AES::performKeyExpansion()
{
	const int size = this->key.length() / 4;
	string* ws = NULL;
	string gw = "";
	string TworoundKey = this->key; // the strting with key and then with the generated 
	// i.e as as started with w0, w1, w2, w3 from key then generated w4, w5, w6, w7 and will use it next time

	//round 1 key will be from 4, 5,6,7
	this->roundkeys[0] = key.substr(16, 16);

	int keyNum = 1;
	for (int rounds = 0; rounds < 7; rounds++)
	{
		// for storing the ws temporariraly
		ws = new string[size];

		//spliting each round key to the required ws
		for (int i = 0, k = 0; i < size * 4; i += 4, k++)
			ws[k] = TworoundKey.substr(i, 4);

		//finding the gw
		gw = findGW(ws[size - 1], rounds);

		//the first w[0] or first
		ws[0] = addStrings(gw, ws[0]);

		// calculate all 
		for (int i = 1; i < size; i++)
		{
			//after 4 iteration substitute byte again the answer get
			if (i % 4 == 0)
				ws[i] = addStrings(substituteWholestring(ws[i - 1]), ws[i]); //current and by substitution 
			else
				ws[i] = addStrings(ws[i - 1], ws[i]); //current and previous result
		}

		TworoundKey = "";

		//combine the generated round key and store it accordingly
		//will use in next iteration to generate next
		for (int i = 0; i < size; i++)
			TworoundKey += ws[i];


		// adding to the array and storing the keys
		roundkeys[keyNum] = TworoundKey.substr(0, 16);
		keyNum++; //half part 1 round

		if (keyNum < 13)
		{
			roundkeys[keyNum] = TworoundKey.substr(16, 16);
			keyNum++; //half part another round
		}

		// will delete dynamic array
		delete[] ws;
		ws = NULL;
	}

}

//will see whole string in the s-box
string AES::substituteWholestring(string toSubstitute)
{
	//byte substituting
	for (int i = 0; i < toSubstitute.length(); i++)
		toSubstitute[i] = fromSbox(toSubstitute[i]); //from the s box

	return toSubstitute; //the result
}

//find the gw
string AES::findGW(string w, const short round)
{
	w = rotLeft(w, 1); // 1 byte left rotate

	w = substituteWholestring(w); //the byte substitution from s box

	// adding the round constant --- only most will take part
	w[0] = addBytes(w[0], this->roundConstants[round]);

	//the gw is ready returning it
	return w;
}

// rotateleft with the given number of shifts and returned the shifted 
// will use for right also by maping the figures
string AES::rotLeft(string shiftIt, const int shifts)
{
	// making copy of the string
	string result = "";

	//shifting left
	//bringing the from the required shifting to the start
	for (int i = (shifts % shiftIt.length()); i < shiftIt.length(); i++)
		result += shiftIt[i];

	//then after that to apply rotation inserting the starting bits till shift
	for (int i = 0; i < (shifts % shiftIt.length()); i++)
		result += shiftIt[i];

	return result;
}

// will see what's in the sbox
unsigned char AES::fromSbox(unsigned char toConvert)
{
	// the first 4 bits are of the row abd the last 4 bits for the column number
	// using bitwise to map these
	return this->s_box[toConvert >> 4][toConvert & 0X0F];
}

// will see what's in the sbox inverse
unsigned char AES::fromSbox_inverse(unsigned char toConvert)
{
	// the first 4 bits are of the row abd the last 4 bits for the column number
	// using bitwise to map these
	return this->s_box_inverse[toConvert >> 4][toConvert & 0X0F];
}


// will substitute from the s box and will cahne given array with the substituted one
void AES::byteSubstitute(string& s)
{
	// iterate till the length and pass the character to substitute 1 character 1 byte [4 bit hex][4 bit hex]
	for (int i = 0; i < s.length(); i++)
		s[i] = fromSbox(s[i]);
}

// adding the bytes 
unsigned char AES::addBytes(const unsigned char byte1, const unsigned char byte2)
{
	//the final result char
	//modulo 2 addition
	return  byte1 ^ byte2;
}

//adding the round constants
string AES::addRoundConstant(string addIn, const short round)
{
	// the addIn is w and we only add constant to the most byte thus passing only that
	addIn[0] = addBytes(addIn[0], this->roundConstants[round]);
	return addIn;
}

//xor the two strings
string AES::addStrings(string a, string b)
{

	//add them and return 
	for (int i = 0; i < a.length(); i++)
		a[i] = addBytes(a[i], b[i]); //xor the bytes

	return a; //the result answer containing
}

// always will be 4*4 because always 128 bits will be used
// will substitue the given matrix with s box
void AES::Byte_Substitution_Encrypt(unsigned char substituteMe[4][4])
{
	//row traversal
	for (int i = 0; i < 4; i++)
	{
		//column traversl
		for (int j = 0; j < 4; j++)
		{
			substituteMe[i][j] = fromSbox(substituteMe[i][j]); //substitute it with the values in s box
		}
	}
}

// for decryption
void AES::Byte_Substitution_Decrypt(unsigned char substituteMe[4][4])
{
	//row traversal
	for (int i = 0; i < 4; i++)
	{
		//column traversl
		for (int j = 0; j < 4; j++)
		{
			substituteMe[i][j] = fromSbox_inverse(substituteMe[i][j]); //substitute it with the values in s box
		}
	}
}

//shifting the rows of the state matrix
void AES::Row_Shifting_Encryption(unsigned char shiftMe[4][4])
{
	//rotating rows from 1 , 2 , 3 not 0
	for (int i = 1; i < 4; i++)
	{
		string row = "";
		//get the whole row
		//get enteries and append in the row
		row += shiftMe[i][0];
		row += shiftMe[i][1];
		row += shiftMe[i][2];
		row += shiftMe[i][3];

		row = rotLeft(row, i); //rotate equal to row as 1, 2 , 3 respectively

		//again assign to the array
		//as know will always be 4 bytes thus hard coding them to be fast
		shiftMe[i][0] = row[0];
		shiftMe[i][1] = row[1];
		shiftMe[i][2] = row[2];
		shiftMe[i][3] = row[3];
	}
	return;
}

//shifting the rows of the state matrix --- inverse
void AES::Row_Shifting_Decryption(unsigned char shiftMe[4][4])
{
	//rotating rows from 1 , 2 , 3 not 0
	for (int i = 1; i < 4; i++)
	{
		string row = "";
		//get the whole row
		//get enteries and append in the row
		row += shiftMe[i][0];
		row += shiftMe[i][1];
		row += shiftMe[i][2];
		row += shiftMe[i][3];

		row = rotLeft(row, 4 - i); //rotate right by the left shifts as 1 left = to 3 right

		//again assign to the array
		//as know will always be 4 bytes thus hard coding them to be fast
		shiftMe[i][0] = row[0];
		shiftMe[i][1] = row[1];
		shiftMe[i][2] = row[2];
		shiftMe[i][3] = row[3];
	}
	return;
}

void AES::print(unsigned char a[4][4])
{
	cout << endl;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cout << hex << (a[i][j] & 0Xff) << " ";
		}
		cout << endl;
	}
}

//mix the columns --- multiplication
void AES::Mix_Columns_Encryption(unsigned char muliplywith[4][4])
{
	//for storing result 
	unsigned char resulted[4][4] = {};

	// the pre defined matrix
	unsigned char multiplyIt[4][4] = {
		{0x02, 0x03, 0x01, 0x01},
		{0x01, 0x02, 0x03, 0x01},
		{0x01, 0x01, 0x02, 0x03},
		{0x03, 0x01, 0x01, 0x02},
	};

	//the first rows
	for (int i = 0; i < 4; i++)
	{
		//the second columns
		for (int j = 0; j < 4; j++)
		{
			//the result at each teration
			//refresh it on each iteration
			unsigned char tempResult = 0x00;

			// multiplication is done as 1st one 1st row and 
			// second one 1st column then 2nd column and soon till n column
			//multiplyIt[i][j] * muliplywith[j][i];
			for (int k = 0; k < 4; k++)
			{
				//multiplyIt[i][j] * muliplywith[k][j]
				if (multiplyIt[i][k] == 0x01)
				{
					//only xor that with wthat ever the thing is becaue * 1 is same
					tempResult = addBytes(muliplywith[k][j], tempResult);
				}
				else if (multiplyIt[i][k] == 0x02)
				{
					//left shift to multiply it two times
					unsigned char temp = (muliplywith[k][j] << 1);

					//if overflows
					if ((0x80 & muliplywith[k][j]) == 0x80)
						temp = addBytes(temp, 0x1b); //add the constant

					//xor that result
					tempResult = addBytes(temp, tempResult);
				}
				else if (multiplyIt[i][k] == 0x03)
				{
					//if 3 then (2+1) --- 1 time we have simple xor and 1 shift for * 2 and then xor to make it 3*x
					unsigned char temp = (muliplywith[k][j] << 1);

					//if overflows
					if ((0x80 & muliplywith[k][j]) == 0x80)
						temp = addBytes(temp, 0x1b); //add the constant

					//then xor accordingly
					tempResult = addBytes(temp, tempResult);
					tempResult = addBytes(muliplywith[k][j], tempResult);
				}

			}
			//save the value
			resulted[i][j] = tempResult;
		}

	}

	//storing back result to the given matrix
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			muliplywith[i][j] = resulted[i][j]; //assign to given
		}
	}

	return;
}

//inverse
void AES::Mix_Columns_Decryption(unsigned char muliplywith[4][4])
{
	//for storing result 
	unsigned char resulted[4][4] = {};

	// the pre defined matrix for inverse column
	unsigned char multiplyIt[4][4] = {
		{0x0e, 0x0b, 0x0d, 0x09},
		{0x09, 0x0e, 0x0b, 0x0d},
		{0x0d, 0x09, 0x0e, 0x0b},
		{0x0b, 0x0d, 0x09, 0x0e},
	};

	//the first rows
	for (int i = 0; i < 4; i++)
	{
		//the second columns
		for (int j = 0; j < 4; j++)
		{
			//the result at each teration
			//refresh it on each iteration
			unsigned char tempResult = 0x00;

			// multiplication is done as 1st one 1st row and 
			// second one 1st column then 2nd column and soon till n column
			//multiplyIt[i][j] * muliplywith[j][i];
			for (int k = 0; k < 4; k++)
			{

				//multiplyIt[i][j] * muliplywith[k][j]
				// in inverse we have 4 fixed digits that will be multiplied as 0e, ob, od, 09
				// 09 = 08 + 01
				// 0b = 08 + 02 + 01
				// 0d = 08 + 04 + 01
				// 0e = 08 + 04 + 02
				// thus we make three variables to hold 8 result, 4 result and 2 result
				unsigned char mulwith_8 = 0x00; // when multiplied by 8
				unsigned char mulwith_4 = 0x00; // when multiplied by 4
				unsigned char mulwith_2 = 0x00; // when multiplied by 2

				// only shift 1 will result in mul with 2 
				mulwith_2 = muliplywith[k][j] << 1; // 08

				//checking over flow if then adding 1b
				if ((muliplywith[k][j] >> 7) == 0x01)
					mulwith_2 = addBytes(mulwith_2, 0x1b);

				// 1 more left shift to mul2 result will be multiply by 4 
				// --- here the overflow also tacled
				// if direct do 2 shifts that will be missing
				mulwith_4 = mulwith_2 << 1; // 04

				//checking over flow if then adding 1b
				if ((mulwith_2 >> 7) == 0x01)
					mulwith_4 = addBytes(mulwith_4, 0x1b);

				// similarly 1 more left shif means multiply by 8
				mulwith_8 = mulwith_4 << 1; // 08

				//checking over flow if then adding 1b
				if ((mulwith_4 >> 7) == 0x01)
					mulwith_8 = addBytes(mulwith_8, 0x1b);


				// multiplying
				if (multiplyIt[i][k] == 0x09)
				{
					unsigned char processing = 0x00;
					processing = addBytes(processing, muliplywith[k][j]); //01
					processing = addBytes(processing, mulwith_8); //08

					// final result of the iteration
					tempResult = addBytes(processing, tempResult);
				}
				else if (multiplyIt[i][k] == 0x0b)
				{

					unsigned char processing = 0x00;
					processing = addBytes(processing, muliplywith[k][j]); //01
					processing = addBytes(processing, mulwith_2); //02
					processing = addBytes(processing, mulwith_8); //08 

					// final result of the iteration
					tempResult = addBytes(processing, tempResult);
				}
				else if (multiplyIt[i][k] == 0x0d)
				{
					unsigned char processing = 0x00;
					processing = addBytes(processing, muliplywith[k][j]); //01
					processing = addBytes(processing, mulwith_4); //04
					processing = addBytes(processing, mulwith_8); //08

					// final result of the iteration
					tempResult = addBytes(processing, tempResult);
				}
				else if (multiplyIt[i][k] == 0x0e)
				{
					unsigned char processing = 0x00;
					processing = addBytes(processing, mulwith_2); //02
					processing = addBytes(processing, mulwith_4); //04
					processing = addBytes(processing, mulwith_8); //08

					// final result of the iteration
					tempResult = addBytes(processing, tempResult);


				}
			}

			//save the value 1 element --- after multiplying 1st row with 1st column
			resulted[i][j] = tempResult;

		}

	}

	//storing back result to the given matrix
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			muliplywith[i][j] = resulted[i][j]; //assign to given
		}
	}

	return;
}

//for adding the round key to the matrix
void AES::Add_roundKey(unsigned char currentStateMatrix[4][4], const int round)
{
	unsigned char roundKey_column_wise[4][4] = {};

	// column wise inserting key into the key matrix -- in the 14 round decryption
	if (round == -1)
		initalizeMe_columnwise(roundKey_column_wise, this->key.substr(0, 16));

	else
		initalizeMe_columnwise(roundKey_column_wise, this->roundkeys[round]); // else use the round key


	//now adding both of the matrices the xor 
	addThesetwo_Matrices(currentStateMatrix, roundKey_column_wise);

	return;
}

// for debugging , printing chharacters to hex
void AES::printHex(string s)
{
	cout << " ";
	for (int i = 0; i < s.length(); i++)
	{
		if (s[i] >> 4 == 0x00)
			cout << hex << '0' << (s[i] & 0xFF) << " ";
		else
			cout << hex << (s[i] & 0xFF) << " ";
	}
	cout << endl;
}

// will intilazie the given 2d column wise
void AES::initalizeMe_columnwise(unsigned char matrix[4][4], string withThis)
{
	const int size = 4;;

	//initalizing the matrices by column wise ----- the key
	for (int i = 0, k = 0; i < size; i++)
	{
		for (int j = 0; j < size; j++, k++)
		{
			matrix[j][i] = withThis[k]; //assigning column wise
		}
	}
}

// will xor the two matrices and result will be in the matrix1
void AES::addThesetwo_Matrices(unsigned char matrix1[4][4], unsigned char matrix2[4][4])
{
	//now adding both of the matrices the xor 
	for (int i = 0, k = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			// xoring and saving in the 1st matrix
			matrix1[i][j] ^= matrix2[i][j]; //added
		}
	}

	return;
}

//will return string from the coulmn wise matrx
string AES::revertColumnwise_matrix(unsigned char matrix[4][4])
{
	string toReturn = "";

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			toReturn += matrix[j][i]; //adding to string column wise
		}
	}

	return toReturn;
}

// the whole encryption process
string AES::encryption(string plainText)
{

	const int size = 4;

	// first making the matrices 
	unsigned char keyMatrix[size][size] = {}; //for key
	unsigned char stateMatrix[size][size] = {}; //the partial cipher text - or - current state matrix

	//initalizing the matrices by column wise ----- the key
	initalizeMe_columnwise(keyMatrix, this->key);

	//initalizing the matrices by column wise ----- the plaintext
	initalizeMe_columnwise(stateMatrix, plainText);

	// the round 0 ------ key whitening ---- xor both matrices
	addThesetwo_Matrices(stateMatrix, keyMatrix); //answer will be in state matrix

	//the result is in state matrix thus passing that to all other 14 rounds
	for (int i = 0; i < 14; i++)
	{
		Byte_Substitution_Encrypt(stateMatrix); //substitue the bytes by s box
		Row_Shifting_Encryption(stateMatrix); //shift the rows

		if (i != 13) //not for the last round
			Mix_Columns_Encryption(stateMatrix); // mix the columns

		// add the round key
		Add_roundKey(stateMatrix, i);
	}

	//return as a string
	return revertColumnwise_matrix(stateMatrix);
}

string AES::decryption(string cipherText)
{
	const int size = 4;

	// first making the matrices 
	unsigned char keyMatrix[size][size] = {}; //for key
	unsigned char stateMatrix[size][size] = {}; //the partial cipher text - or - current state matrix

	//initalizing the matrices by column wise ----- the key
	initalizeMe_columnwise(keyMatrix, roundkeys[13]);

	//initalizing the matrices by column wise ----- the plaintext
	initalizeMe_columnwise(stateMatrix, cipherText);

	// the round 0 ------ key whitening inverse ---- xor both matrices
	addThesetwo_Matrices(stateMatrix, keyMatrix); //answer will be in state matrix

	//the result is in state matrix thus passing that to all other 14 rounds
	for (int i = 0; i < 14; i++)
	{
		Row_Shifting_Decryption(stateMatrix); //the row shifting
		Byte_Substitution_Decrypt(stateMatrix); //substitue the bytes by s box
		Add_roundKey(stateMatrix, 12 - i);

		if (i != 13) //not for the last round
			Mix_Columns_Decryption(stateMatrix); // mix the columns
	}

	//return as string
	return revertColumnwise_matrix(stateMatrix);
}

// the destructor
AES::~AES()
{
	delete[] this->roundkeys; //dynmaic memory deallocation
}
