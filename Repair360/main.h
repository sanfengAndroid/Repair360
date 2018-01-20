#pragma once
#ifndef _MAIN_H_
#define _MAIN_H_
#include "DexFile.h"

#define LINE_MAX_CHAR_NUM 100

u1* getFileData(const char* path, size_t& len);
int repairDexFile(int argc, char** argv);
int readMapFile(const char* path);
void handle360GenerateMapOrDecrypt(DexFile* pSourceDexFile, char table[kNumPackedOpcodes][LINE_MAX_CHAR_NUM], DexFile* pEncryptDexFile, u1* &pFileEnd, u1 key_360);
int findOpcodeRealIndex(Opcode opcode);
void decryptDexCode(DexFile* pDexFile, DexClassDef* pDexClassDef, ClassData* pClassData, DexCode* pDexCode, u1* &pFileEnd, int methodInClassDataIdx, u1 key, bool isLookUpTable);

ClassData* dexGetClassData(const DexFile* pDexFile, ClassData* pClassData, const u1* data);
const char* dexGetLongTypeDescriptor(const char type);
const char* type2LongString(const char* name);
const char* accessFlags2String(char* str, int access);

void printDexHeadStructure(const DexFile* pDexFile);
void printDexClassDefStructure(const DexClassDef* pDexClassDef);
void printMethodStringById(const DexFile* pDexFile, u4 idx, int methodAccessFlags);
void printDexCodeStructure(const DexFile* pDexFile, const DexCode* pDexCode);
void printDexCodeStructure(const DexCode* pDexCode);
void printDexClassDataStructure(const DexFile* pDexFile, const ClassData* pClassData);

int generateMapFile(int argc, char** argv);
void generateMapTable(char table[LINE_MAX_CHAR_NUM][LINE_MAX_CHAR_NUM], const DexCode* sourceData, const DexCode* encryptData, u1 key, bool isLookUpTable);
DexCode* getSourceDexCode(const DexFile* pSDexFile, DexCode* pSDexCode, u4 classDefIdx);

u1* getFileData(const char* path, size_t& len);
int repairDexFile(int argc, char** argv);
int readMapFile(const char* path);
void handle360GenerateMapOrDecrypt(DexFile* pSourceDexFile, char table[kNumPackedOpcodes][LINE_MAX_CHAR_NUM], DexFile* pEncryptDexFile, u1* &pFileEnd, u1 key_360);
int findOpcodeRealIndex(Opcode opcode);
void decryptDexCode(DexFile* pDexFile, DexClassDef* pDexClassDef, ClassData* pClassData, DexCode* pDexCode, u1* &pFileEnd, int methodInClassDataIdx, u1 key, bool isLookUpTable);
#endif // !_MAIN_H_
