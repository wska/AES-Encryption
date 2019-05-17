#ifndef UTILITY_H
#define UTILIY_H

void writeRawBytes(unsigned char * pointer, int n);

// Writes n bytes from a pointer. Used for debugging.
void writeBytes(unsigned char * pointer, int n);

// Print function used for debugging.
// Given a matrix @matrix, prints @bytes number of bytes as rows of 4.
void printMatrix(unsigned char * matrix, int bytes);

#endif