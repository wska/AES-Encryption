
/*
AES 128 bit encryption
@author William Skagerström
Last modified: 2019-05-15
*/


// AES Irreducible polynomial: p(x) = x^8 + x^4 + x^3 + x + 1

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "tables.h"
#include "unistd.h"

using namespace std;





void blockXOR(unsigned char * block, unsigned char * key){
    for (int i = 0; i<16; i++){
        block[i] ^= key[i];
    }
}

void byteSubstitution(unsigned char * block){
    for (int i = 0; i<16; i++){
        block[i] = sbox[block[i]];
    }
}

void shiftRows(unsigned char * block){

    
    /*
    Shifts the rows of the keyblock according to the specifiation below:

    0  4   8 12         0  4  8 11
    1  5   9 13   =>    5  9 13  1
    2  6  10 14        19 14  2  6
    3  7  11 15        15  3  7 11
    */

    unsigned char shiftedRows[16];

    // Row 1
    shiftedRows[0] = block[0];
    shiftedRows[4] = block[4];
    shiftedRows[8] = block[8];
    shiftedRows[12] = block[12];

    // Row 2
    shiftedRows[1] = block[5];
    shiftedRows[5] = block[9];
    shiftedRows[9] = block[13];
    shiftedRows[13] = block[1];

    // Row 3
    shiftedRows[2] = block[10];
    shiftedRows[6] = block[14];
    shiftedRows[10] = block[2];
    shiftedRows[14] = block[6];

    // Row 4
    shiftedRows[3] = block[15];
    shiftedRows[7] = block[3];
    shiftedRows[11] = block[7];
    shiftedRows[15] = block[11];


	for (int i = 0; i < 16; i++) {
		block[i] = shiftedRows[i];
	}
}

void mixOneColumn(unsigned char * r){
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;

    for(c=0; c<4; c++){
        a[c] = r[c];
        h = (unsigned char)((signed char)r[c] >> 7); // Extracts the high bit of r.
        b[c] = r[c] << 1; // Removes the high high bit of b[c].
        b[c] ^= 0x1b & h;
    }

    /* 
    Multiplication in GS(2^8)
    2*a0 + 3*a1 + 1*a2 + 1*a3

    1*a0 + 2*a1 * 3*a2 + 1*a3

    1*a0 + 1*a1 + 2*a2 + 3*a3

    3*a0 + 1*a1 + 1*a2 + 2*a3
    */

    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; 
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; 
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; 
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

}

void mixColumns(unsigned char * block){

    
    unsigned char mixColumns[16];

    unsigned char temp[4]; // Temporary variable for a single column

    for(int j=0; j<4; j++){
        temp[0] = block[j];
        temp[1] = block[j+4];
        temp[2] = block[j+8];
        temp[3] = block[j+12];

        mixOneColumn(temp);

        mixColumns[j] = temp[0];
        mixColumns[j+4] = temp[1];
        mixColumns[j+8] = temp[2];
        mixColumns[j+12] = temp[3];


    }
    
    /*
    temp[0] = mixColumns[0];
    temp[1] = mixColumns[4];
    temp[2] = mixColumns[8];
    temp[3] = mixColumns[12];
    
    mixColumns[1] = 1;
    mixColumns[5] = 1;
    mixColumns[9] = 1;
    mixColumns[13] = 1;

    mixColumns[2] = 1;
    mixColumns[6] = 1;
    mixColumns[10] = 1;
    mixColumns[14] = 1;

    mixColumns[3] = 1;
    mixColumns[7] = 1;
    mixColumns[11] = 1;
    mixColumns[15] = 1;
    */
    

    for (int i = 0; i < 16; i++) {
		block[i] = mixColumns[i];
	}


}

// Print function used for debugging.
// Given a matrix @matrix, prints @bytes number of bytes as rows of 4.
void printMatrix(unsigned char * matrix, int bytes){
    for(int i=0; i<bytes; i++){
        if(i%4 == 0){
            cout << endl;
        }
        cout << hex << int(matrix[i]) << " ";
        

    }
    cout << endl;
}

// XOR of a 128 bit block with a 128 bit key.
void addRoundKey(unsigned char * block, unsigned char * key){
    for(int i=0; i<16; i++){
        block[i] ^= key[i];
    }
}


// One round of the 128-bit AES.
void encRound(unsigned char * block, unsigned char * key){
    byteSubstitution(block);
    shiftRows(block);
    mixColumns(block);
    addRoundKey(block, key);
}

// Final round does not execute the mixColumns operation.
void lastRound(unsigned char * block, unsigned char * key){
    byteSubstitution(block);
    shiftRows(block);
    addRoundKey(block, key);
}



void expandKeyShift(unsigned char * word, int roundIteration){
    unsigned char savedOriginalIndex = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = savedOriginalIndex;

    // Byte substitution using the S-box
    word[0] = sbox[word[0]];
    word[1] = sbox[word[1]];
    word[2] = sbox[word[2]];
    word[3] = sbox[word[3]];

    word[0] ^= rcon[roundIteration-1]; // Because rcon is 0-indexed. Rounds are counted as natural numbers.

}

// Function for generating the additional 10 subkeys, for 11 in total.
void expandKey(unsigned char * originalKey, unsigned char * expandedKey){

    // originalKey = 16 bytes. expandedKey = 16*11 = 176 bytes.
    for(int i=0; i<16; i++){
        expandedKey[i] = originalKey[i];
    }

    unsigned char word[4];

    
    int bytesgenerated = 16;
    int rcon = 1;
    
    while(bytesgenerated < 176){
        for (int i = 0; i<4; i++){
            word[i] = expandedKey[i + bytesgenerated - 4];
        }

        if(bytesgenerated % 16 == 0){
            expandKeyShift(word, rcon);
            rcon++;
        }

        for (int a = 0; a<4; a++){
            expandedKey[bytesgenerated + a] = expandedKey[bytesgenerated-16 + a] ^ word[a];
            
        }
        bytesgenerated = bytesgenerated + 4;
    }
    
    /*
    for (int roundIteration = 1; roundIteration<44; roundIteration++){

        for (int k = 0; k<4; k++){
            word[k] = expandedKey[k + roundIteration*4 - 4];
        }


        expandKeyShift(word, roundIteration);
        
        for (int j=0; j<4; j++){
            expandedKey[roundIteration*16 + j] = expandedKey[roundIteration*4 + j - 16] ^ word[j];
        }

    }*/
    
    



}

// Main encryption function
void encrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage){

    unsigned char block[16];

    for (int i=0; i<16; i++){
        block[i] = message[i];
    }

    addRoundKey(block, expandedKey);

    // 9 normal rounds
    for(int i=0; i<9; i++){
        encRound(block, expandedKey);
    }

    // Last round without the mixcolumns
    lastRound(block, expandedKey);

    
    for(int i=0; i<16; i++){
        encryptedMessage[i] = block[i];
    }
    

}

int main(){

    //unsigned char key[16];
    //read(0, key, sizeof(key)); // Reads 16 bytes into key from stdin


   
    unsigned char key[16] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75};
    unsigned char block[16] = {0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F};
    
    /*
    unsigned char test[16] = {
                              0x54,    0x68,      0x61,      0x74,
                              0x73,    0x20,      0x6d,      0x79,
                              0x20,    0x4b,     0x75,     0x6e,
                              0x67,    0x20,     0x46,     0x75
                             };
    */
    //mixColumns(test);
    //printMatrix(test, 16);

    // Creates the expanded key.
    unsigned char expandedKey[176];
    expandKey(key, expandedKey);

    for (int i=0; i<176; i++){
        if (i%16 == 0 && i!=0){
            cout << endl;
        }
    cout << hex << (int) expandedKey[i] << " ";
  
    }
    cout << endl;
    


    unsigned char encryptedMessage[16];

    //unsigned char block[16];

    

    /*
    while(read(0, block, 16)){

        
        //for(int i = 0; i<16; i++){
        //    cout << hex << (int) block[i];
        //}

        cout << endl;
        encrypt(block, expandedKey, encryptedMessage);


        for(int i = 0; i<16; i++){
            cout << hex << (int) encryptedMessage[i];
        }
    }
    */

    //unsigned char expandedKey[176];
    //unsigned char test2[4] = {test[12], test[13], test[14], test[15]};

    /*
    cout << hex << int(test2[0]) << endl;
    cout << hex << int(test2[1]) << endl;
    cout << hex << int(test2[2]) << endl;
    cout << hex << int(test2[3]) << endl;
    cout << endl;

    expandKeyShift(test2, 1);

    cout << hex << int(test2[0]) << endl;
    cout << hex << int(test2[1]) << endl;
    cout << hex << int(test2[2]) << endl;
    cout << hex << int(test2[3]) << endl;
    */
    /*
    expandKey(test, expandedKey);
    cout << hex << int(expandedKey[16]) << endl;
    cout << hex << int(expandedKey[17]) << endl;
    cout << hex << int(expandedKey[18]) << endl;
    cout << hex << int(expandedKey[19]) << endl;
    */


    /*
    unsigned char r[4] = {0xf2, 0x0a, 0x22, 0x5c};
    mixOneColumn(r);
    cout << hex << int(r[0])<< endl;
    cout << hex << int(r[1])<< endl;
    cout << hex << int(r[2])<< endl;
    cout << hex << int(r[3])<< endl;
    */
   


}


































