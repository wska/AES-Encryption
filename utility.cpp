
/*
AES 128 bit encryption utility functions
@author William Skagerström
Last modified: 2019-05-17
*/


#include <iostream>
#include "utility.h"

using namespace std;

void writeRawBytes(unsigned char * pointer, int n){
    for(int i = 0; i<n; i++){
        cout << *(pointer+i);
    }
}

// Writes n bytes from a pointer. Used for debugging.
void writeBytes(unsigned char * pointer, int n){
    
    for(int i=0; i<n; i++){
        
        cout << hex << int(*(pointer+i)) << " ";
    }
    cout << endl;
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