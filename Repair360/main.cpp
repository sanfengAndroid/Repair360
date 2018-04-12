#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "DexFile.h"
#include "Leb128.h"
#include "Utils.h"
#include "main.h"

#define BYTE4_ALIGN(a) ( ((a) % 4) ? ((((a) >> 2) << 2) + 4): (a))

u1* opcode_table = NULL;
u1* pOriginalOpcode = NULL;
u1* pEncryptOpcode = NULL;
bool isLookUpTable = false;
bool decryptMode = false;

int Opcode_Len[256] = {
	1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
	2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
	0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
	3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 3, 3,
	3, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 0,

};

//-g D:\Android破解实例\classes.dex D:\Android破解实例\360test\dump.dex D:\Android破解实例\360test\map.txt 0x80 D:\Android破解实例\360test\opcode_table
//-d D:\Android破解实例\360test\dump.dex D:\Android破解实例\360test\repair.dex D:\Android破解实例\360test\map.txt 0x80 D:\Android破解实例\360test\opcode_table 

int main(int argc, char **argv)
{
	if (argc < 6) {
		printf("Too few parameters\n");
		printf("format: \n");
		printf("-g source.dex encrypt.dex file_path key [opcode_table]		generate map file\n");
		printf("-d encrypt.dex out.dex map.txt key [opcode_table]		repair dex file\n");
		return -1;
	}
	if (strcmp(argv[1], "-g") == 0) {
		printf("You chose to generate the command map\n");
		if (argc != 6 && argc != 7)
		{
			printf("parameters error, format: -g source.dex encrypt.dex file_path key [opcode_table]\n");
			return -1;
		}
		decryptMode = false;
		generateMapFile(argc, argv);
	}
	else if (strcmp(argv[1], "-d") == 0) {
		printf("You have chosen to repair the file mode\n");
		if (argc != 6 && argc != 7)
		{
			printf("parameters error, format: -d encrypt.dex out.dex map.txt key [opcode_table]\n");
			return -1;
		}
		decryptMode = true;
		repairDexFile(argc, argv);
	}
	return 0;
}

int repairDexFile(int argc, char** argv)
{
	size_t repair_dex_len = 0;
	u1* repair_data = getFileData(argv[2], repair_dex_len);
	if (repair_data == NULL)
	{
		return -1;
	}
	//手动确认文件格式正确,否者后面会出现错误, 这里需要将NULL替换成任意没有使用的字节,否者会影响后面读取文件生成指令映射表
	readMapFile(argv[4]);
	u1 key = (u1)htoi(argv[5]);
	if (argc == 6)
	{
		isLookUpTable = false;
	}
	else
	{
		isLookUpTable = true;
		size_t table_len = 0;
		opcode_table = getFileData(argv[6], table_len);
		if (opcode_table == NULL)
		{
			return -1;
		}
		if (table_len != 0x100)
		{
			printf("opcode_table file format error, Its size must be 256 bytes of binary\n");
			return -1;
		}
	}
	FILE *fp_out = fopen(argv[3], "wb");
	if (fp_out == NULL)
	{
		printf("Can not write the file: %s\n", argv[3]);
		return -1;
	}
	// 这里重新申请下内存空间,预留足够的空间来保存修复后的classData结构体到文件后面
	size_t out_dex_len = repair_dex_len + repair_dex_len / 10;
	u1* out_data = (u1*)malloc(out_dex_len);
	memset(out_data, 0, out_dex_len);
	memcpy(out_data, repair_data, repair_dex_len);
	free(repair_data);
	DexFile* pOutDexFile = dexFileParse(out_data, repair_dex_len, 0);
	u1* pFileEnd = (u1*)pOutDexFile->baseAddr + repair_dex_len;
	handle360GenerateMapOrDecrypt(NULL, NULL, pOutDexFile, pFileEnd, (u1)htoi(argv[5]));
	u4 new_dex_len = (u4)(pFileEnd - pOutDexFile->baseAddr);
	*(u4*)(out_data + 0x20) = new_dex_len;							//由于结构体中有些字段包含const修饰,因此直接用指针改
	printf("修正后新dex文件大小为: 0x%x\n", pFileEnd - pOutDexFile->baseAddr);

	fwrite(out_data, new_dex_len, 1, fp_out);
	fclose(fp_out);
	printf("完成文件修复: %s, 生成文件路径: %s\n", argv[2], argv[3]);
	printf("请注意修复后的dex文件头的签名和文件校验和并未重新计算, 并且dex中还包含静态块中的360调用语句,要想完全修复还需要去除360的调用语句\n");
	free(out_data);
	free(pOriginalOpcode);
	free(pEncryptOpcode);
	free(opcode_table);
	return 0;
}

/*根据我们生成的格式读取: 原指令opcode 加固后指令opcode 指令长度 指令描述, 这里要特别注意一定要把map表中的NULL换成加密指令没有使用的任意一个字节*/
int readMapFile(const char* path) 
{
	//指令长度程序已经保存了一份,因此只需读取原指令opcode 和加固后指令opcode
	FILE *fp = fopen(path, "rt");
	if (fp == NULL)
	{
		printf("%s map file open error!\n", path);
		return -1;
	}
	pOriginalOpcode = (u1*)malloc(kNumPackedOpcodes);
	pEncryptOpcode = (u1*)malloc(kNumPackedOpcodes);
	char line[LINE_MAX_CHAR_NUM];
	for (int i = 0; i < kNumPackedOpcodes; i++)
	{
		memset(line, 0, LINE_MAX_CHAR_NUM);
		fgets(line, LINE_MAX_CHAR_NUM, fp);
		pOriginalOpcode[i] = (u1)htoi(strtok(line, " "));
		pEncryptOpcode[i] = (u1)htoi(strtok(NULL, " "));	//这里需要map文件中的NULL替换为任意未使用的字节
		
	}
	return 0;
}

u1* getFileData(const char* path, size_t &len)
{
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		printf("open %s  file error!\n", path);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("%s file length: 0x%x\n", path, len);
	u1* data = (u1*)malloc(len);
	if (data == NULL) {
		printf("malloc memory fail!\n");
		return NULL;
	}
	fread(data, len, 1, fp);
	fclose(fp);
	return data;
}

int generateMapFile(int argc, char** argv)
{	
	//这里注意要必须指定为二进制格式读, 如果以只读方式读取文件可能会导致部分文件读取数据错误
	size_t source_dex_len = 0;
	u1* source_data = getFileData(argv[2], source_dex_len);
	if (source_data == NULL){
		return -1;
	}
	size_t encrypt_dex_len = 0;
	u1* encrypt_data = getFileData(argv[3], encrypt_dex_len);
	if (encrypt_data == NULL) {
		return -1;
	}
	if (argc == 6)
	{
		printf("currently there is no mapping mode\n");
		isLookUpTable = false;
	}
	else
	{
		printf("currently there is mapping mode\n");
		isLookUpTable = true;
		size_t table_len = 0;
		opcode_table = getFileData(argv[6], table_len);
		if (opcode_table == NULL)
		{
			return -1;
		}
		if (table_len != 0x100)
		{
			printf("opcode_table file format error, Its size must be 256 bytes of binary\n");
			return -1;
		}
	}

	FILE *out_fp = fopen(argv[4], "wt+");
	if (out_fp == NULL)
	{
		printf("open %s file failed\n", argv[4]);
		return -1;
	}
	char table[kNumPackedOpcodes][LINE_MAX_CHAR_NUM] = { 0 };
	DexFile* pSourceDexFile = dexFileParse(source_data, source_dex_len, 0);
	DexFile* pEncryptDexFile = dexFileParse(encrypt_data, encrypt_dex_len, 0);
	u1* pFileEnd = NULL;
	handle360GenerateMapOrDecrypt(pSourceDexFile, table, pEncryptDexFile, pFileEnd, htoi(argv[5]));
	//保存映射表到文件, 在table表中有些行是空行,如没有使用的opcode和dex文件中不存在的和没有包含的指令(throw, return, return-wide, return-object),通常不影响,加固后也使用不到这些指令
	for (int i = 0; i < kNumPackedOpcodes; i++)
	{
		if (*table[i] =='\0')
		{
			strcpy(table[i], "0x");
			if (i < 0x10)
			{
				strcat(table[i], "0");
			}
			char string[7];
			itoa(i, string, 16);
			strcat(table[i], string);
			strcat(table[i], " ");			
			strcat(table[i], "NULL");
			strcat(table[i], " ");
			itoa(Opcode_Len[i], string, 10);
			strcat(table[i], string);
			strcat(table[i], " ");
			strcat(table[i], dexGetOpcodeName((Opcode)i));
		}
		fputs(table[i], out_fp);
		fputc('\n', out_fp);
	}
	fclose(out_fp);
	free(source_data);
	free(encrypt_data);
	free(opcode_table);
	printf(">>> 已生成指令映射表(注:解密时需要将map表中的NULL替换为任意未使用的字节),路径: %s", argv[4]);
	return 0;
}

void generateMapTable(char table[LINE_MAX_CHAR_NUM][LINE_MAX_CHAR_NUM],const DexCode* sourceData, const DexCode* encryptData, u1 key, bool lookUpTable)
{
	printf(">>> 当前函数异或key: 0x%x\n", key);
	u4 insnsSize = sourceData->insnsSize;
	//默认情况下伪指令是在指令的最后部分, 因此指令查找到伪指令起始指令即可,但是要注意伪指令必须位于偶数字节码偏移(4字节对齐), 因此之前一个指令可能为nop指令
	u4 insns_end_offset = insnsSize;
	u4 offset = 0;
	bool hasDirective = false;
	for (u4 i = 0; i < insns_end_offset; i++)
	{
		Opcode opcode = dexOpcodeFromCodeUnit(sourceData->insns[i]);
		Opcode encrypt_opcode;
		//u2 insns = GETINSNS(encryptData->insns[i], key);
		if (lookUpTable) {
			encrypt_opcode = (Opcode)opcode_table[(dexOpcodeFromCodeUnit(encryptData->insns[i]) & 0xff) ^ key];
		}
		else
		{
			encrypt_opcode = (Opcode)((dexOpcodeFromCodeUnit(encryptData->insns[i]) & 0xff) ^ key);
		}
		// 这里要考虑packed-switch-payload, sparse-switch-payload, fill-array-data-payload三种伪指令的情况
		printf(">>> 当前指令: %s\n", dexGetOpcodeName(opcode));
		//packed-switch vAA, +BBBBBBBB  fill-array-data vAA, +BBBBBBBB  sparse-switch vAA, +BBBBBBBB
		if (opcode == OP_PACKED_SWITCH || opcode == OP_SPARSE_SWITCH || opcode == OP_FILL_ARRAY_DATA) {			
			printf(">>> %s 指令索引: %d  ", dexGetOpcodeName(opcode), i);
			offset = (sourceData->insns[i + 1] | (sourceData->insns[i + 2] << 16)) + i;
			printf(">>> %s 数据在指令中索引: %d\n", dexGetOpcodeName(opcode), offset);
			if (offset < insns_end_offset)
			{
				insns_end_offset = offset;
				printf(">>> 更新伪指令起始指令索引: %d\n", insns_end_offset);
			}
			hasDirective = true;
		}
		if (hasDirective && i == (insns_end_offset - 1))	//由于伪指令4字节对齐的原因可能这条指令为空指令
		{
			if (opcode == OP_NOP)
			{
				break;
			}
		}
		int len = Opcode_Len[opcode];
		char string[7];

		strcpy(table[opcode], "0x");
		if (opcode < 0x10)
		{
			strcat(table[opcode], "0");
		}
		itoa(opcode, string, 16);
		strcat(table[opcode], string);
		strcat(table[opcode], " ");
		strcat(table[opcode], "0x");
		if (encrypt_opcode < 0x10)
		{
			strcat(table[opcode], "0");
		}
		itoa(encrypt_opcode, string, 16);
		strcat(table[opcode], string);
		strcat(table[opcode], " ");
		itoa(len, string, 10);
		strcat(table[opcode], string);
		strcat(table[opcode], " ");
		strcat(table[opcode], dexGetOpcodeName(opcode));
		i = i + len - 1;
	}
	
}

void decryptDexCode(DexFile* pDexFile, DexClassDef* pDexClassDef, ClassData* pClassData, DexCode* pDexCode, u1* &pFileEnd, int methodInClassDataIdx, u1 key, bool isLookUpTable)
{
	printf(">>> 当前函数异或key: 0x%x\n", key);
	//首先确定的是DexCode段中的所有指令都异或了key, 但是三种伪指令实际上是没有加密的
	for (u4 i = 0; i < pDexCode->insnsSize; i++)
	{
		pDexCode->insns[i] = pDexCode->insns[i] ^ (key << 8 | key);
	}
	bool hasDirective = false;
	u4 insns_end_offset = pDexCode->insnsSize;
	u4 offset = 0;

	//360没有更改指令的常量索引,因为360应该是反编译为smali代码后添加静态块代码导致了type_idx,method_idx,string_idx索引有所变化
	//360只是对三种伪指令特征码(0x300, 0x200, 0x100)的低字节做了非0处理,这个值可能不固定
	for (u4 i = 0; i < insns_end_offset; i++)
	{
		Opcode opcode;
		if (isLookUpTable)
		{
			 opcode = (Opcode)opcode_table[dexOpcodeFromCodeUnit(pDexCode->insns[i])];
		}
		else
		{
			opcode = dexOpcodeFromCodeUnit(pDexCode->insns[i]);
		}	
		int index = findOpcodeRealIndex(opcode);
		assert(index != -1);
		if ((Opcode)index == OP_PACKED_SWITCH || (Opcode)index == OP_SPARSE_SWITCH || (Opcode)index == OP_FILL_ARRAY_DATA)
		{
			printf(">>> %s 指令索引: %d  ", dexGetOpcodeName((Opcode)index), i);
			offset = (pDexCode->insns[i + 1] | (pDexCode->insns[i + 2] << 16)) + i;
			printf(">>> %s 数据在指令中索引: %d\n", dexGetOpcodeName((Opcode)index), offset);
			//这里对三种伪指令特征码还原, 由于前面已经把所有指令都异或了一遍,为了后面处理方便,所以这里伪指令的特征码低位该保存key
			pDexCode->insns[offset] = (pDexCode->insns[offset] & 0xff00) | key;
			if (offset < insns_end_offset)
			{
				insns_end_offset = offset;
				printf(">>> 更新伪指令起始指令索引: %d\n", insns_end_offset);
			}
			hasDirective = true;
		}
		pDexCode->insns[i] = (pDexCode->insns[i] & 0xff00) | pOriginalOpcode[index];
		i = i + Opcode_Len[index] - 1;
	}
	//前面将末尾附带的三种伪指令数据都进行了异或处理,而实际情况是360没有处理伪指令,因此需要异或回来
	if (hasDirective)
	{
		for (u4 i = insns_end_offset; i < pDexCode->insnsSize; i++)
		{
			pDexCode->insns[i] = pDexCode->insns[i] ^ (key << 8 | key);
		}
	}

	pDexClassDef->classDataOff = (u4)(pFileEnd - pDexFile->baseAddr);
	printf(">>> 修复最新classDataOff在文件中偏移: 0x%x", pDexClassDef->classDataOff);
	pClassData->encodedMethod[methodInClassDataIdx].codeOff = pDexCode;
	printf(">>> 更新方法最新DexCode在文件中偏移: 0x%x\n", (u1*)pDexCode - pDexFile->baseAddr);
	pClassData->encodedMethod[methodInClassDataIdx].accessFlags = pClassData->encodedMethod[methodInClassDataIdx].accessFlags & ~ACC_NATIVE;
	printf(">>> 更新方法最新访问权限: 0x%x\n", pClassData->encodedMethod[methodInClassDataIdx].accessFlags);
	//下面开始写入新的classData到文件末尾
	pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->staticFieldsSize);
	pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->instanceFieldsSize);
	pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->directMethodsSize);
	pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->virtualMethodsSize);
	for (int i = 0; i < pClassData->staticFieldsSize + pClassData->instanceFieldsSize; i++)
	{
		pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->encodedField[i].fieldIdxDiff);
		pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->encodedField[i].accessFlags);

	}
	printf(">>> 写入classData最新字段完成: staticFieldsSize: %d, instanceFieldsSize: %d, directMethodsSize: %d, virtualMethodsSize: %d\n", pClassData->staticFieldsSize, pClassData->instanceFieldsSize, pClassData->directMethodsSize, pClassData->virtualMethodsSize);
	for (int i = 0; i < pClassData->directMethodsSize + pClassData->virtualMethodsSize; i++)
	{
		pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->encodedMethod[i].methodIdxDiff);
		pFileEnd = writeUnsignedLeb128(pFileEnd, (u4)pClassData->encodedMethod[i].accessFlags);
		u4 codeOff = (u4)((u1*)pClassData->encodedMethod[i].codeOff - pDexFile->baseAddr);
		pFileEnd = writeUnsignedLeb128(pFileEnd, codeOff);
	}
	printf(">>> 写入方法ClassData中method完成\n");
}

int findOpcodeRealIndex(Opcode opcode)
{
	for (int i = 0; i < kNumPackedOpcodes; i++)
	{
		if (pEncryptOpcode[i] == opcode)
		{
			return i;
		}
	}
	return -1;
}

void handle360GenerateMapOrDecrypt(DexFile* pSourceDexFile, char table[kNumPackedOpcodes][LINE_MAX_CHAR_NUM], DexFile* pEncryptDexFile, u1* &pFileEnd, u1 key_360)
{
	DexClassDef* pDexClassDef = NULL;
	DexCode* pDexCode = NULL;
	ClassData* pClassData = NULL;
	DexMethodId* pDexMethodId = NULL;
	DexCode* pLastDexCode = NULL;
	u4 lastDexCodeOff = 0;
	int num = 0;
	for (u4 i = 0; i < pEncryptDexFile->pHeader->classDefsSize; i++)
	{
		pDexClassDef = (DexClassDef*)dexGetClassDef(pEncryptDexFile, i);
		if (pDexClassDef->classDataOff != 0)
		{
			pClassData = dexGetClassData(pEncryptDexFile, pClassData, pEncryptDexFile->baseAddr + pDexClassDef->classDataOff);
			int baseMethodIdx = 0;
			for (int j = 0; j < pClassData->directMethodsSize + pClassData->virtualMethodsSize; j++)
			{
				if (j == 0 || j == pClassData->directMethodsSize)
				{
					baseMethodIdx = pClassData->encodedMethod[j].methodIdxDiff;
				}
				else
				{
					baseMethodIdx += pClassData->encodedMethod[j].methodIdxDiff;
				}
				//抽象方法和native方法都会导致codeOff偏移为0
				if (pClassData->encodedMethod[j].codeOff == NULL && (pClassData->encodedMethod[j].accessFlags & ACC_NATIVE))
				{
					pDexMethodId = (DexMethodId*)dexGetMethodId(pEncryptDexFile, baseMethodIdx);
					const char* method_name = dexStringById(pEncryptDexFile, pDexMethodId->nameIdx);
					if (strcmp(method_name, "onCreate") == 0)	//目前360只处理了onCreate,但是分析代码时在其它几大组件中的<clinit>方法中都调用了360的接口函数,因此未来可能会加固其它组件的方法
					{
						if (decryptMode)
						{
							printf(">>> 找到待修复的method: class_def_item = %d  methodId = %d \n", i, baseMethodIdx);
							//这里还应该考虑上一个DexCode有没有try_catch块,因为这里会影响真正的DexCode在文件中的偏移
							if (pLastDexCode->triesSize > 0)
							{
								printf(">>> 上一个DexCode包含try_catch模块,需要修复真实DexCode偏移, 如果出错,很可能在这里读取出错\n");
								const u1* p_new_DexCode = pEncryptDexFile->baseAddr + lastDexCodeOff;
								for (u2 k = 0; k < pLastDexCode->triesSize; i++)
								{
									p_new_DexCode += 4;			//try_item[k]->start_addr
									p_new_DexCode += 2;			//try_item[k]->insn_count
									p_new_DexCode += 2;			//try_item[k]->handler_off
								}
								// catch_handler_list
								u4 catch_handler_list_size = readUnsignedLeb128(&p_new_DexCode);	//catch_handler_list->size
								for (u4 l = 0; l < catch_handler_list_size; l++)
								{
									//catch_handler
									int catch_handler_size = readSignedLeb128(&p_new_DexCode);	//这里size有正数, 0, 负数三种区别
									bool is_nagtive = catch_handler_size > 0 ? false : true;
									for (int m = 0; m < abs(catch_handler_size); m++)
									{
										//type_addr_pair
										assert((p_new_DexCode - pEncryptDexFile->baseAddr) > 0 && (u4)(p_new_DexCode - pEncryptDexFile->baseAddr) < pEncryptDexFile->pHeader->fileSize);
										readUnsignedLeb128(&p_new_DexCode);
										assert((p_new_DexCode - pEncryptDexFile->baseAddr) > 0 && (u4)(p_new_DexCode - pEncryptDexFile->baseAddr) < pEncryptDexFile->pHeader->fileSize);
										readUnsignedLeb128(&p_new_DexCode);
									}
									if (is_nagtive)
									{
										readUnsignedLeb128(&p_new_DexCode);			// 为负数时包含一个所有catch模块
									}
								}
								lastDexCodeOff = BYTE4_ALIGN(p_new_DexCode - pEncryptDexFile->baseAddr);
							}
							
							printMethodStringById(pEncryptDexFile, baseMethodIdx, pClassData->encodedMethod[j].accessFlags);
							pDexCode = (DexCode*)(pEncryptDexFile->baseAddr + lastDexCodeOff);
							u1 key = (pDexMethodId->classIdx ^ baseMethodIdx ^ pDexCode->registersSize ^ key_360) & 0xff;
							decryptDexCode(pEncryptDexFile, pDexClassDef, pClassData, pDexCode, pFileEnd, j, key, isLookUpTable);
							num++;
							lastDexCodeOff = 0;
						}
						else
						{
							printf(">>> 找到要生成指令映射表的method:\n");
							printMethodStringById(pEncryptDexFile, baseMethodIdx, pClassData->encodedMethod[j].accessFlags);
							pDexCode = (DexCode *)(pEncryptDexFile->baseAddr + lastDexCodeOff);
							u1 key = (pDexMethodId->classIdx ^ baseMethodIdx ^ pDexCode->registersSize ^ key_360) & 0xff;
							// 这里加固后ClassDef索引不会变,但是methodIdx是可能变化的,因为代码中增加了静态方法<clinit>, 可能导致方法数增加,因此需要重新查找源文件onCreate方法的索引
							DexCode* pSDexCode = getSourceDexCode(pSourceDexFile, NULL, i);
							generateMapTable(table, pSDexCode, pDexCode, key, isLookUpTable);
							num++;
							lastDexCodeOff = 0;
						}
						
					}
				}
				else if (pClassData->encodedMethod[j].codeOff != NULL)
				{
					if (lastDexCodeOff == 0) {
						lastDexCodeOff = (const u1 *)pClassData->encodedMethod[j].codeOff - pEncryptDexFile->baseAddr;
					}
					pDexCode = pClassData->encodedMethod[j].codeOff;
					
					pLastDexCode = pDexCode;
					// 读取DexCode的insns,找到insns的结束位置,而DexCode需要4字节对齐
					lastDexCodeOff = BYTE4_ALIGN((const u1*)&pDexCode->insns[pDexCode->insnsSize] - pEncryptDexFile->baseAddr);
					//这里应该还要考虑DexCode中包含try_catch语句的情况, 且try_catch字段也需要4字节对齐
					
				}
			}
		}
	}
	if (decryptMode)
	{
		printf("In total %d functions are decrypted\n", num);
	}
	else
	{
		printf("In total %d functions are used to generate the map table\n", num);
	}
}

DexCode* getSourceDexCode(const DexFile* pSDexFile, DexCode* pSDexCode, u4 classDefIdx)
{
	if (pSDexCode == NULL)
	{
		pSDexCode = (DexCode* )malloc(sizeof(DexCode));
	}
	const DexClassDef* pSDexClassDef = (const DexClassDef*)malloc(sizeof(DexClassDef));
	pSDexClassDef = dexGetClassDef(pSDexFile, classDefIdx);
	ClassData* pSClassData = (ClassData*)malloc(sizeof(ClassData));
	pSClassData = dexGetClassData(pSDexFile, pSClassData, pSDexFile->baseAddr + pSDexClassDef->classDataOff);
	u4 baseMethodIdx = 0;
	const DexMethodId* pDexMethodId = (const DexMethodId*)malloc(sizeof(DexMethodId));
	for (int i = 0; i < pSClassData->directMethodsSize + pSClassData->virtualMethodsSize; i++)
	{
		if (i == 0)
		{
			baseMethodIdx = pSClassData->encodedMethod[i].methodIdxDiff;
		}
		else if (i == pSClassData->directMethodsSize) {
			baseMethodIdx = pSClassData->encodedMethod[i].methodIdxDiff;
		}
		else
		{
			baseMethodIdx += pSClassData->encodedMethod[i].methodIdxDiff;
		}
		pDexMethodId = dexGetMethodId(pSDexFile, baseMethodIdx);
		const char* method_name = dexStringById(pSDexFile, pDexMethodId->nameIdx);
		if (strcmp(method_name, "onCreate") == 0)
		{
			pSDexCode = pSClassData->encodedMethod[i].codeOff;
			break;
		}
	}
	return pSDexCode;
}

void printDexCodeStructure(const DexFile* pDexFile, const DexCode* pDexCode) {
	printf("current DexCode in dex file offset: 0x%x\n", (u1*)pDexCode - pDexFile->baseAddr);
	printf("register number: %d, ins number: %d, outs number: %d, try catch number: %d, debug offset: 0x%x", pDexCode->registersSize, pDexCode->insSize, pDexCode->outsSize, pDexCode->triesSize, pDexCode->debugInfoOff);
	printf("insns number: 0x%x  insns: \n", pDexCode->insnsSize);
	for (u4 i = 0; i < pDexCode->insnsSize; i++)
	{
		printf("0x%x ", pDexCode->insns[i]);
	}
	printf("\n");
}

ClassData* dexGetClassData(const DexFile* pDexFile, ClassData* pClassData, const u1* data) {
	if (pClassData == NULL) {
		pClassData = (ClassData*)malloc(sizeof(ClassData));
	}
	pClassData->staticFieldsSize = readUnsignedLeb128(&data);
	pClassData->instanceFieldsSize = readUnsignedLeb128(&data);
	pClassData->directMethodsSize = readUnsignedLeb128(&data);
	pClassData->virtualMethodsSize = readUnsignedLeb128(&data);
	if ((pClassData->staticFieldsSize + pClassData->instanceFieldsSize) > 0) {
		pClassData->encodedField = (ClassDataOfField*)malloc(sizeof(ClassDataOfField) * (pClassData->staticFieldsSize + pClassData->instanceFieldsSize));
		for (int i = 0; i < pClassData->staticFieldsSize + pClassData->instanceFieldsSize; i++) {
			pClassData->encodedField[i].fieldIdxDiff = readUnsignedLeb128(&data);
			pClassData->encodedField[i].accessFlags = readUnsignedLeb128(&data);
		}
	}
	if ((pClassData->directMethodsSize + pClassData->virtualMethodsSize) > 0) {
		pClassData->encodedMethod = (ClassDataOfMethod*)malloc(sizeof(ClassDataOfMethod) * (pClassData->directMethodsSize + pClassData->virtualMethodsSize));
		for (int i = 0; i < pClassData->directMethodsSize + pClassData->virtualMethodsSize; i++) {
			pClassData->encodedMethod[i].methodIdxDiff = readUnsignedLeb128(&data);
			pClassData->encodedMethod[i].accessFlags = readUnsignedLeb128(&data);
			u4 offset = readUnsignedLeb128(&data);
			if (offset != 0) {
				pClassData->encodedMethod[i].codeOff = (DexCode *)(pDexFile->baseAddr + offset);
			}
			else {
				pClassData->encodedMethod[i].codeOff = NULL;
			}
		}
	}
	return pClassData;
}

void printMethodStringById(const DexFile* pDexFile, u4 idx, int methodAccessFlags)
{
	const DexMethodId* pDexMethodId = (const DexMethodId*)malloc(sizeof(DexMethodId));
	pDexMethodId = dexGetMethodId(pDexFile, idx);
	const char* methodName = dexStringById(pDexFile, pDexMethodId->nameIdx);


	const char* className = dexStringByTypeIdx(pDexFile, pDexMethodId->classIdx);


	const DexProtoId* pDexProtoId = (const DexProtoId*)malloc(sizeof(DexProtoId));
	pDexProtoId = dexGetProtoId(pDexFile, pDexMethodId->protoIdx);
	const char* returnTypeName = dexStringByTypeIdx(pDexFile, pDexProtoId->returnTypeIdx);


	int parametersNum = 0;

	const DexTypeList* pDexTypeList = (const DexTypeList *)malloc(sizeof(DexTypeList));
	pDexTypeList = dexGetProtoParameters(pDexFile, pDexProtoId);
	const char** parametersName = NULL;
	if (pDexTypeList != NULL) {
		if (pDexTypeList->size) {
			parametersName = (const char**)malloc(sizeof(1) * pDexTypeList->size);

			parametersNum = pDexTypeList->size;
			for (u4 i = 0; i < pDexTypeList->size; i++) {
				DexTypeItem pDexTypeItem = pDexTypeList->list[i];
				parametersName[i] = dexStringByTypeIdx(pDexFile, pDexTypeItem.typeIdx);
			}
		}
	}

	if (strlen(returnTypeName) == 1) {
		returnTypeName = dexGetLongTypeDescriptor(returnTypeName[0]);
	}
	else {
		returnTypeName = type2LongString(returnTypeName);
	}
	className = type2LongString(className);
	for (int i = 0; i < parametersNum; i++) {
		if (strlen(parametersName[i]) == 1) {
			parametersName[i] = dexGetLongTypeDescriptor(parametersName[i][0]);
		}
		else {
			parametersName[i] = type2LongString(parametersName[i]);
		}
	}
	char access[100] = { 0 };
	accessFlags2String(access, methodAccessFlags);
	printf("%s%s %s.%s(", access, returnTypeName, className, methodName);
	for (int i = 0; i < parametersNum; i++) {
		if (i != parametersNum - 1) {
			printf("%s, ", parametersName[i]);
		}
		else {
			printf("%s", parametersName[i]);
		}

	}
	printf(")\n");

}

const char* accessFlags2String(char* str, int access)
{
	if (access & ACC_PUBLIC) {		//这其中有些关键字通常函数都没有的
		strcat(str, "public ");
	}
	else if (access & ACC_PRIVATE) {
		strcat(str, "private ");
	}
	else if (access & ACC_PROTECTED) {
		strcat(str, "protect ");
	}
	if (access & ACC_STATIC)
		strcat(str, "static ");
	if (access & ACC_FINAL)
		strcat(str, "final ");
	if (access & ACC_SYNCHRONIZED)
		strcat(str, "synchronized ");
	if (access & ACC_BRIDGE)
		strcat(str, "bridge ");
	if (access & ACC_VARARGS)
		strcat(str, "varages ");
	if (access & ACC_NATIVE)
		strcat(str, "native ");
	if (access & ACC_ABSTRACT)
		strcat(str, "abstract ");
	if (access & ACC_STRICT)
		strcat(str, "strict ");
	return (const char*)str;
}

/*Lcom/beichen/test;  --->  com.beichen.test*/
const char* type2LongString(const char* name)
{
	int len = strlen(name);
	char *dest = (char *)malloc(len - 1);
	//拷贝是去掉开头 "L" 和结尾 ";"
	memcpy(dest, name + 1, len - 2);
	dest[len - 2] = 0;
	for (int i = 0; i < len - 1; i++) {
		if (dest[i] == '/')
			dest[i] = '.';
	}
	return (const char*)dest;
}

void printDexClassDataStructure(const DexFile* pDexFile, const ClassData* pClassData)
{
	printf("current class_data_item in dex file offset: 0x%x\n", (u1*)pClassData - pDexFile->baseAddr);
	printf("staticFieldsSize: %d, instanceFieldsSize: %d, directMethodsSize: %d, virtualMethodsSize: %d\n", pClassData->staticFieldsSize, pClassData->instanceFieldsSize, pClassData->directMethodsSize, pClassData->virtualMethodsSize);
	//printf("encodedField pointer: 0x%p, encodedMethod pointer: 0x%p\n", pClassData->encodedField, pClassData->encodedMethod);
	printf("print Fields:\n");
	for (int i = 0; i < pClassData->staticFieldsSize + pClassData->instanceFieldsSize; i++) {
		printf("Field index : %d  FieldIdxDiff : %d  FieldAccessFlags : 0x%x\n", i, pClassData->encodedField[i].fieldIdxDiff, pClassData->encodedField[i].accessFlags);
	}
	printf("print Methods:\n");
	for (int i = 0; i < pClassData->directMethodsSize + pClassData->virtualMethodsSize; i++) {
		printf("Method index : %d MethodIdxOff : 0x%x  MethodAccessFlags : 0x%x\n  DexCode pointer : 0x%x\n", i, pClassData->encodedMethod[i].methodIdxDiff, pClassData->encodedMethod[i].accessFlags, (const u1*)pClassData->encodedMethod[i].codeOff - pDexFile->baseAddr);
	}
}

void printDexCodeStructure(const DexCode* pDexCode) {
	printf("registersSize: %d, insSize: %d, outsSize: %d, triesSize: %d\n", pDexCode->registersSize, pDexCode->insSize, pDexCode->outsSize, pDexCode->triesSize);
	printf("debufInfoOff: 0x%x, insnsSize: 0x%x, insns[0]: 0x%x\n", pDexCode->debugInfoOff, pDexCode->insnsSize, pDexCode->insns[0]);
}
void printDexClassDefStructure(const DexClassDef* pDexClassDef) {
	printf("classIdx: 0x%x, accessFlags: 0x%x, superclassIdx: 0x%x, interfacesOff: 0x%x\n", pDexClassDef->classIdx, pDexClassDef->accessFlags, pDexClassDef->superclassIdx, pDexClassDef->interfacesOff);
	printf("sourceFileIdx: 0x%x, annotationsOff: 0x%x, classDataOff: 0x%x, staticValuesOff: 0x%x\n", pDexClassDef->sourceFileIdx, pDexClassDef->annotationsOff, pDexClassDef->classDataOff, pDexClassDef->staticValuesOff);
}
void printDexHeadStructure(const DexFile* pDexFile)
{
	printf("stringIdsSize: %d, stringIdsOff: 0x%x\n", pDexFile->pHeader->stringIdsSize, pDexFile->pHeader->stringIdsOff);
	printf("typeIdsSize: %d, typeIdsOff: 0x%x\n", pDexFile->pHeader->typeIdsSize, pDexFile->pHeader->typeIdsOff);
	printf("protoIdsSize: %d, protoIdsOff: 0x%x\n", pDexFile->pHeader->protoIdsSize, pDexFile->pHeader->protoIdsOff);
	printf("fieldIdsSize: %d, fieldIdsOff: 0x%x\n", pDexFile->pHeader->fieldIdsSize, pDexFile->pHeader->fieldIdsOff);
	printf("methodIdsSize: %d, methodIdsOff: 0x%x\n", pDexFile->pHeader->methodIdsSize, pDexFile->pHeader->methodIdsOff);
	printf("classDefsSize: %d, classDefsOff: 0x%x\n", pDexFile->pHeader->classDefsSize, pDexFile->pHeader->classDefsOff);
	printf("dataSize: %d, dataOff: 0x%x\n", pDexFile->pHeader->dataSize, pDexFile->pHeader->dataOff);
}

DexFile* dexFileParse(const u1* data, size_t length, int flags)
{
	DexFile* pDexFile = NULL;
	const DexHeader* pHeader;
	int result = -1;
	if (length < sizeof(DexHeader)) {
		printf("too short to be a valid .dex");
		goto bail;
	}
	pDexFile = (DexFile*)malloc(sizeof(DexFile));
	if (pDexFile == NULL)
		goto bail;
	memset(pDexFile, 0, sizeof(DexFile));

	dexFileSetupBasicPointers(pDexFile, data);
	pHeader = pDexFile->pHeader;

	result = 0;
bail:
	if (result != 0 && pDexFile != NULL) {
		dexFileFree(pDexFile);
		pDexFile = NULL;
	}
	return pDexFile;
}
void dexFileFree(DexFile* pDexFile)
{
	if (pDexFile == NULL)
		return;

	free(pDexFile);
}

void dexFileSetupBasicPointers(DexFile* pDexFile, const u1* data) {
	DexHeader *pHeader = (DexHeader*)data;

	pDexFile->baseAddr = data;
	pDexFile->pHeader = pHeader;
	pDexFile->pStringIds = (const DexStringId*)(data + pHeader->stringIdsOff);
	pDexFile->pTypeIds = (const DexTypeId*)(data + pHeader->typeIdsOff);
	pDexFile->pFieldIds = (const DexFieldId*)(data + pHeader->fieldIdsOff);
	pDexFile->pMethodIds = (const DexMethodId*)(data + pHeader->methodIdsOff);
	pDexFile->pProtoIds = (const DexProtoId*)(data + pHeader->protoIdsOff);
	pDexFile->pClassDefs = (const DexClassDef*)(data + pHeader->classDefsOff);
	pDexFile->pLinkData = (const DexLink*)(data + pHeader->linkOff);
}

/* (documented in header) */
const char* dexGetPrimitiveTypeDescriptor(PrimitiveType type) {
	switch (type) {
	case PRIM_VOID:    return "V";
	case PRIM_BOOLEAN: return "Z";
	case PRIM_BYTE:    return "B";
	case PRIM_SHORT:   return "S";
	case PRIM_CHAR:    return "C";
	case PRIM_INT:     return "I";
	case PRIM_LONG:    return "J";
	case PRIM_FLOAT:   return "F";
	case PRIM_DOUBLE:  return "D";
	default:           return NULL;
	}

	return NULL;
}

const char* dexGetLongTypeDescriptor(const char type) {
	switch (type) {
	case 'V':	return "void";
	case 'Z':	return "boolean";
	case 'B':	return "byte";
	case 'S':	return "short";
	case 'C':	return "char";
	case 'I':	return "int";
	case 'J':	return "long";
	case 'F':	return "float";
	case 'D':	return "double";
	default:	return NULL;
	}
	return NULL;
}

/* (documented in header) */
const char* dexGetBoxedTypeDescriptor(PrimitiveType type) {
	switch (type) {
	case PRIM_VOID:    return NULL;
	case PRIM_BOOLEAN: return "Ljava/lang/Boolean;";
	case PRIM_BYTE:    return "Ljava/lang/Byte;";
	case PRIM_SHORT:   return "Ljava/lang/Short;";
	case PRIM_CHAR:    return "Ljava/lang/Character;";
	case PRIM_INT:     return "Ljava/lang/Integer;";
	case PRIM_LONG:    return "Ljava/lang/Long;";
	case PRIM_FLOAT:   return "Ljava/lang/Float;";
	case PRIM_DOUBLE:  return "Ljava/lang/Double;";
	default:           return NULL;
	}
}

/* (documented in header) */
PrimitiveType dexGetPrimitiveTypeFromDescriptorChar(char descriptorChar) {
	switch (descriptorChar) {
	case 'V': return PRIM_VOID;
	case 'Z': return PRIM_BOOLEAN;
	case 'B': return PRIM_BYTE;
	case 'S': return PRIM_SHORT;
	case 'C': return PRIM_CHAR;
	case 'I': return PRIM_INT;
	case 'J': return PRIM_LONG;
	case 'F': return PRIM_FLOAT;
	case 'D': return PRIM_DOUBLE;
	default:  return PRIM_NOT;
	}
}


static const char* gOpNames[kNumPackedOpcodes] = {
	// BEGIN(libdex-opcode-names); GENERATED AUTOMATICALLY BY opcode-gen
	"nop",
	"move",
	"move/from16",
	"move/16",
	"move-wide",
	"move-wide/from16",
	"move-wide/16",
	"move-object",
	"move-object/from16",
	"move-object/16",
	"move-result",
	"move-result-wide",
	"move-result-object",
	"move-exception",
	"return-void",
	"return",
	"return-wide",
	"return-object",
	"const/4",
	"const/16",
	"const",
	"const/high16",
	"const-wide/16",
	"const-wide/32",
	"const-wide",
	"const-wide/high16",
	"const-string",
	"const-string/jumbo",
	"const-class",
	"monitor-enter",
	"monitor-exit",
	"check-cast",
	"instance-of",
	"array-length",
	"new-instance",
	"new-array",
	"filled-new-array",
	"filled-new-array/range",
	"fill-array-data",
	"throw",
	"goto",
	"goto/16",
	"goto/32",
	"packed-switch",
	"sparse-switch",
	"cmpl-float",
	"cmpg-float",
	"cmpl-double",
	"cmpg-double",
	"cmp-long",
	"if-eq",
	"if-ne",
	"if-lt",
	"if-ge",
	"if-gt",
	"if-le",
	"if-eqz",
	"if-nez",
	"if-ltz",
	"if-gez",
	"if-gtz",
	"if-lez",
	"unused-3e",
	"unused-3f",
	"unused-40",
	"unused-41",
	"unused-42",
	"unused-43",
	"aget",
	"aget-wide",
	"aget-object",
	"aget-boolean",
	"aget-byte",
	"aget-char",
	"aget-short",
	"aput",
	"aput-wide",
	"aput-object",
	"aput-boolean",
	"aput-byte",
	"aput-char",
	"aput-short",
	"iget",
	"iget-wide",
	"iget-object",
	"iget-boolean",
	"iget-byte",
	"iget-char",
	"iget-short",
	"iput",
	"iput-wide",
	"iput-object",
	"iput-boolean",
	"iput-byte",
	"iput-char",
	"iput-short",
	"sget",
	"sget-wide",
	"sget-object",
	"sget-boolean",
	"sget-byte",
	"sget-char",
	"sget-short",
	"sput",
	"sput-wide",
	"sput-object",
	"sput-boolean",
	"sput-byte",
	"sput-char",
	"sput-short",
	"invoke-virtual",
	"invoke-super",
	"invoke-direct",
	"invoke-static",
	"invoke-interface",
	"unused-73",
	"invoke-virtual/range",
	"invoke-super/range",
	"invoke-direct/range",
	"invoke-static/range",
	"invoke-interface/range",
	"unused-79",
	"unused-7a",
	"neg-int",
	"not-int",
	"neg-long",
	"not-long",
	"neg-float",
	"neg-double",
	"int-to-long",
	"int-to-float",
	"int-to-double",
	"long-to-int",
	"long-to-float",
	"long-to-double",
	"float-to-int",
	"float-to-long",
	"float-to-double",
	"double-to-int",
	"double-to-long",
	"double-to-float",
	"int-to-byte",
	"int-to-char",
	"int-to-short",
	"add-int",
	"sub-int",
	"mul-int",
	"div-int",
	"rem-int",
	"and-int",
	"or-int",
	"xor-int",
	"shl-int",
	"shr-int",
	"ushr-int",
	"add-long",
	"sub-long",
	"mul-long",
	"div-long",
	"rem-long",
	"and-long",
	"or-long",
	"xor-long",
	"shl-long",
	"shr-long",
	"ushr-long",
	"add-float",
	"sub-float",
	"mul-float",
	"div-float",
	"rem-float",
	"add-double",
	"sub-double",
	"mul-double",
	"div-double",
	"rem-double",
	"add-int/2addr",
	"sub-int/2addr",
	"mul-int/2addr",
	"div-int/2addr",
	"rem-int/2addr",
	"and-int/2addr",
	"or-int/2addr",
	"xor-int/2addr",
	"shl-int/2addr",
	"shr-int/2addr",
	"ushr-int/2addr",
	"add-long/2addr",
	"sub-long/2addr",
	"mul-long/2addr",
	"div-long/2addr",
	"rem-long/2addr",
	"and-long/2addr",
	"or-long/2addr",
	"xor-long/2addr",
	"shl-long/2addr",
	"shr-long/2addr",
	"ushr-long/2addr",
	"add-float/2addr",
	"sub-float/2addr",
	"mul-float/2addr",
	"div-float/2addr",
	"rem-float/2addr",
	"add-double/2addr",
	"sub-double/2addr",
	"mul-double/2addr",
	"div-double/2addr",
	"rem-double/2addr",
	"add-int/lit16",
	"rsub-int",
	"mul-int/lit16",
	"div-int/lit16",
	"rem-int/lit16",
	"and-int/lit16",
	"or-int/lit16",
	"xor-int/lit16",
	"add-int/lit8",
	"rsub-int/lit8",
	"mul-int/lit8",
	"div-int/lit8",
	"rem-int/lit8",
	"and-int/lit8",
	"or-int/lit8",
	"xor-int/lit8",
	"shl-int/lit8",
	"shr-int/lit8",
	"ushr-int/lit8",
	"+iget-volatile",
	"+iput-volatile",
	"+sget-volatile",
	"+sput-volatile",
	"+iget-object-volatile",
	"+iget-wide-volatile",
	"+iput-wide-volatile",
	"+sget-wide-volatile",
	"+sput-wide-volatile",
	"^breakpoint",
	"^throw-verification-error",
	"+execute-inline",
	"+execute-inline/range",
	"+invoke-object-init/range",
	"+return-void-barrier",
	"+iget-quick",
	"+iget-wide-quick",
	"+iget-object-quick",
	"+iput-quick",
	"+iput-wide-quick",
	"+iput-object-quick",
	"+invoke-virtual-quick",
	"+invoke-virtual-quick/range",
	"+invoke-super-quick",
	"+invoke-super-quick/range",
	"+iput-object-volatile",
	"+sget-object-volatile",
	"+sput-object-volatile",
	"unused-ff",
	// END(libdex-opcode-names)
};

/*
* Return the name of an opcode.
*/
const char* dexGetOpcodeName(Opcode op)
{
	assert(op >= 0 && op < kNumPackedOpcodes);
	return gOpNames[op];
}
