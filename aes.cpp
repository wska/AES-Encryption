
/*
AES 128 bit encryption
@author William Skagerström
Last modified: 2019-05-17
*/


#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "tables.h"
#include "unistd.h"
#include "utility.h"

using namespace std;

// XOR of a 128 bit block with a 128 bit key.
void addRoundKey(unsigned char * block, unsigned char * key){
    for(int i=0; i<16; i++){
        block[i] ^= key[i];
    }
}

// Byte substituion
void byteSubstitution(unsigned char * block){
    for (int i = 0; i<16; i++){
        block[i] = sbox[block[i]];
    }
}

void shiftRows(unsigned char * block){

    
    /*
    Shifts the rows of the keyblock according to the specifiation below:

    0  4   8 12   =>     0  4  8 11
    1  5   9 13   =>     5  9 13  1
    2  6  10 14   =>    19 14  2  6
    3  7  11 15   =>    15  3  7 11
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

    // AES Irreducible polynomial: p(x) = x^8 + x^4 + x^3 + x + 1

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

    unsigned char mixCols[16];

    unsigned char temp[4]; // Temporary variable for a single column

    // Transponents the block in order to multiply directly to the GS(2^8) matrix.
    for(int j=0; j<4; j++){
        temp[0] = block[j*4];
        temp[1] = block[j*4+1];
        temp[2] = block[j*4+2];
        temp[3] = block[j*4+3];

        mixOneColumn(temp);

        mixCols[j] = temp[0];
        mixCols[j+4] = temp[1];
        mixCols[j+8] = temp[2];
        mixCols[j+12] = temp[3];
    }
    

    // Undoes the transponent.
    for (int i = 0; i < 4; i++) {
		block[i*4] = mixCols[i];
        block[i*4+1] = mixCols[i + 4];
        block[i*4+2] = mixCols[i + 8];
        block[i*4+3] = mixCols[i + 12];
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

    // originalKey = 16 bytes. 10 subkeys at 16 bytes each. expandedKey = 16*11 = 176 bytes.
    for(int i=0; i<16; i++){
        expandedKey[i] = originalKey[i];
    }

    unsigned char word[4];

    int rcon = 1; // Keeps track of which entry in the RCON matrix to use.
    
    for(int bytesProcessed = 16; bytesProcessed < 176; bytesProcessed+=4){
        for (int i = 0; i<4; i++){
            word[i] = expandedKey[i + bytesProcessed - 4];
        }

        if(bytesProcessed % 16 == 0){
            expandKeyShift(word, rcon);
            rcon++;
        }

        for (int a = 0; a<4; a++){
            expandedKey[bytesProcessed + a] = expandedKey[bytesProcessed-16 + a] ^ word[a];
            
        }
        
    }
    
}

// Main encryption function
void encrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage){

    unsigned char block[16];

    for (int i=0; i<16; i++){
        block[i] = message[i];
    }

    addRoundKey(block, expandedKey);

    // 9 normal rounds
    for(int i=1; i<10; i++){
        encRound(block, expandedKey+(16*i)); // Also increments the pointer to the location of the roundkey needed
    }

    // Last round without the mixcolumns
    lastRound(block, expandedKey+(16*10)); // Last round is round 10, so increment by 16 bytes*10 to put the pointer at the final key.

    
    for(int i=0; i<16; i++){
        encryptedMessage[i] = block[i];
    }
}



int main(){

    unsigned char key[16];
    read(0, key, sizeof(key)); // Reads 16 bytes into key from stdin
   
    // Creates the expanded key.
    unsigned char expandedKey[176];
    expandKey(key, expandedKey);

    unsigned char encryptedMessage[16]; // Memory segment where the encrypted message is written to
    unsigned char block[16]; // Stores the block to be encrypted
    
    // While there is input, take a block of 16 bytes and encrypt it using AES and extended key derived from the original key. 
    while(read(0, block, 16)){
       encrypt(block, expandedKey, encryptedMessage);
        writeRawBytes(encryptedMessage, 16);

    }
    
}


































