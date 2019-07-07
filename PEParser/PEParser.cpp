// PEParser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "my_structures.h"

using namespace std;

// formatting options
#define FORMAT_TEXT		0
#define FORMAT_BYTE		1
#define FORMAT_WORD		2
#define FORMAT_DWORD	4
#define FORMAT_LONG		4

// padding between name and value
#define PADDING 50

// left side indent
int indent_level = 1;

// message buffer for note value in printLine func
char msg[200];

// file bytes
char *memblock;

// header structures pointers
IMAGE_DOS_HEADER*			dos_header;
IMAGE_NT_HEADERS32*			pe_header;
IMAGE_FILE_HEADER*			file_header;
IMAGE_OPTIONAL_HEADER32*	opt_header;

IMAGE_SECTION_HEADER*		sec_headers;

IMAGE_DATA_DIRECTORY*		exp_table;
IMAGE_DATA_DIRECTORY*		imp_table;

// -----------------------
//   UTILITY FUNCTIONS
// -----------------------

int convertRVAtoPA(DWORD rva){
	for(int i = 0; i < file_header->NumberOfSections; i++){
		if( rva >= sec_headers[i].VirtualAddress 
			&& rva < sec_headers[i].VirtualAddress + sec_headers[i].SizeOfRawData){
				return rva - (sec_headers[i].VirtualAddress - sec_headers[i].PointerToRawData);
		}
	}
	
	return -1;
}

void printLine(char* name, int value, int bytes, char* note = ""){
	int level = indent_level*4;

	// indent line
	while((level--))printf(" ");

	// print entry name
	printf("%s:", name);

	// use padding 
	int padding = PADDING - strlen(name) - indent_level * 4;
	while((padding--) > 0)printf(" ");
	
	if (bytes == 0){
		printf("%s ", (char*)value);
	}else if (bytes == 1){
		printf("      0x%02X ", value);
	}else if(bytes == 2){
		printf("    0x%04X ", value);
	}else{
		printf("0x%08X ", value);
	}

	printf("%s\n", note);
}


void printMZHeader(){
	printf("MZ HEADER\n=========\n");

	printLine("Magic", dos_header->e_magic,FORMAT_WORD);
	printLine("Bytes on last page of file",dos_header->e_cblp,FORMAT_WORD);
	printLine("Pages in file",dos_header->e_cp,FORMAT_WORD);
	printLine("Relocations",dos_header->e_crlc,FORMAT_WORD);
	printLine("Size of header in paragraphs",dos_header->e_cparhdr,FORMAT_WORD);
	printLine("Minimum extra paragraphs",dos_header->e_minalloc,FORMAT_WORD);
	printLine("Maximum extra paragraphs",dos_header->e_maxalloc,FORMAT_WORD);
	printLine("Initial (Relative) SS",dos_header->e_ss,FORMAT_WORD);
	printLine("Initial SP", dos_header->e_sp,FORMAT_WORD);
	printLine("Checksum", dos_header->e_csum,FORMAT_WORD);
	printLine("Initial IP", dos_header->e_ip,FORMAT_WORD);
	printLine("Initial (Relative) CS", dos_header->e_cs,FORMAT_WORD);
	printLine("Relocation Table Offset", dos_header->e_lfarlc,FORMAT_WORD);
	printLine("Overlay number", dos_header->e_ovno,FORMAT_WORD);
	for(int i = 0; i < 4; i++)printLine("Reserved", dos_header->e_res[i],FORMAT_WORD);
	printLine("OEM Identifier", dos_header->e_oemid,FORMAT_WORD);
	printLine("OEM information", dos_header->e_oeminfo,FORMAT_WORD);
	for(int i = 0; i < 10; i++)printLine("Reserved", dos_header->e_res2[i],FORMAT_WORD);
	printLine("Offset to PE Header", dos_header->e_lfanew,FORMAT_LONG);
	printf("\n");
}

void printPEHeader(){
	printf("PE HEADER\n=========\n");


	printLine("Magic", pe_header->Signature,FORMAT_DWORD);
	
	// IMAGE_FILE_HEADER
	printLine("Machine", file_header->Machine,FORMAT_WORD);
	printLine("Number of Sections", file_header->NumberOfSections,FORMAT_WORD);
	printLine("Time Date Stamp", file_header->TimeDateStamp,FORMAT_DWORD);
	printLine("Pointer to Symbol Table", file_header->PointerToSymbolTable,FORMAT_DWORD);
	printLine("Number of Symbols", file_header->NumberOfSymbols,FORMAT_DWORD);
	printLine("Size of Optional Header", file_header->SizeOfOptionalHeader,FORMAT_WORD);
	printLine("Characteristics", file_header->Characteristics,FORMAT_WORD);
	printf("\n");

	// IMAGE_OPTIONAL_HEADER
	printf("OPTIONAL HEADER\n===============\n");

	printLine("Magic", opt_header->Magic,FORMAT_WORD);
	printLine("Major Linker Version", opt_header->MajorLinkerVersion,FORMAT_BYTE);
	printLine("Minor Linker Version", opt_header->MinorLinkerVersion,FORMAT_BYTE);
	printLine("Size of Code", opt_header->SizeOfCode,FORMAT_DWORD);
	printLine("Size of Initialied Data", opt_header->SizeOfInitializedData,FORMAT_DWORD);
	printLine("Size of Uninitialised Data", opt_header->SizeOfUninitializedData,FORMAT_DWORD);
	
	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(opt_header->AddressOfEntryPoint));
	printLine("Address Of Entry Point", opt_header->AddressOfEntryPoint,FORMAT_DWORD, msg);
	
	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(opt_header->BaseOfCode));
	printLine("Base of Code", opt_header->BaseOfCode,FORMAT_DWORD, msg);

	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(opt_header->BaseOfData));
	printLine("Base of Data", opt_header->BaseOfData,FORMAT_DWORD, msg);

	printLine("Image Base", opt_header->ImageBase,FORMAT_DWORD);
	printLine("Section Alignment", opt_header->SectionAlignment,FORMAT_DWORD);
	printLine("File Alignment", opt_header->FileAlignment,FORMAT_DWORD);
	printLine("Major OS Version", opt_header->MajorOperatingSystemVersion,FORMAT_WORD);
	printLine("Minor OS Version", opt_header->MinorOperatingSystemVersion,FORMAT_WORD);
	printLine("Major Image Version", opt_header->MajorImageVersion,FORMAT_WORD);
	printLine("Minor Image Version", opt_header->MinorImageVersion,FORMAT_WORD);
	printLine("Major Subsystem Version", opt_header->MajorSubsystemVersion,FORMAT_WORD);
	printLine("Minor Subsystem Version", opt_header->MinorSubsystemVersion,FORMAT_WORD);
	printLine("Win32 Version", opt_header->Win32VersionValue, FORMAT_DWORD);
	printLine("Size of Image", opt_header->SizeOfImage, FORMAT_DWORD);
	printLine("Size of Headers", opt_header->SizeOfHeaders, FORMAT_DWORD);
	printLine("Checksum", opt_header->CheckSum, FORMAT_DWORD);
	printLine("Subsystem", opt_header->Subsystem, FORMAT_WORD);
	printLine("DLL Characteristics", opt_header->DllCharacteristics, FORMAT_WORD);
	printLine("Size of Stack Reserve", opt_header->SizeOfStackReserve, FORMAT_DWORD);
	printLine("Size of Stack Commit", opt_header->SizeOfStackCommit, FORMAT_DWORD);
	printLine("Size of Heap Reserve", opt_header->SizeOfHeapReserve, FORMAT_DWORD);
	printLine("Size of Heap Commit", opt_header->SizeOfHeapCommit, FORMAT_DWORD);
	printLine("Loader Flags", opt_header->LoaderFlags, FORMAT_DWORD);
	printLine("Number of Data Directories", opt_header->NumberOfRvaAndSizes, FORMAT_DWORD);
	printf("\n");

	indent_level = 2;
	// EXPORT TABLE - index 0
	exp_table = &opt_header->DataDirectory[0];
	if(exp_table->VirtualAddress > 0){
		printf("    Export Table\n");
		sprintf_s(msg," (phys: %08X)", convertRVAtoPA(exp_table->VirtualAddress));
		printLine("Relative Virtual Address", exp_table->VirtualAddress, FORMAT_DWORD);
		printLine("Size of Table", exp_table->Size, FORMAT_DWORD);
		printf("\n");
	}else{
		printf("    No Export Table\n\n");
	}

	
	// IMPORT TABLE - index 1
	imp_table = &opt_header->DataDirectory[1];
	if(imp_table->VirtualAddress > 0){
		printf("    Import Table\n");
		sprintf_s(msg," (phys: %08X)", convertRVAtoPA(imp_table->VirtualAddress));
		printLine("Relative Virtual Address", imp_table->VirtualAddress, FORMAT_DWORD, msg);
		printLine("Size of Table", imp_table->Size, FORMAT_DWORD);
		printf("\n");
	}else{
		printf("    No Import Table\n");
	}	

	printf("\n");
	indent_level = 1;
}

void printSectionHeaders(){
	printf("SECTION HEADERS\n===============\n");

	for(int i = 0; i < file_header->NumberOfSections; i++){
		//printf("%d\n", (int)&sec_headers[i].Name);
		printLine("Name", (int)&sec_headers[i].Name, FORMAT_TEXT);
		printLine("Virtual Size", sec_headers[i].Misc.VirtualSize, FORMAT_DWORD);
		sprintf_s(msg," (phys: %08X)", convertRVAtoPA(sec_headers[i].VirtualAddress));
		printLine("Section RVA", sec_headers[i].VirtualAddress, FORMAT_DWORD, msg);
		printLine("Size of Raw Data", sec_headers[i].SizeOfRawData, FORMAT_DWORD);
		printLine("Pointer to Raw Data", sec_headers[i].PointerToRawData, FORMAT_DWORD);
		printLine("Pointer to Relocations", sec_headers[i].PointerToRelocations, FORMAT_DWORD);
		printLine("Pointer to Line Numbers", sec_headers[i].PointerToLinenumbers, FORMAT_DWORD);
		printLine("Number of Relocations", sec_headers[i].NumberOfRelocations, FORMAT_WORD);
		printLine("Nuber of Line Numbers", sec_headers[i].NumberOfLinenumbers, FORMAT_WORD);
		printLine("Characteristics", sec_headers[i].Characteristics, FORMAT_DWORD);
		printf("\n");
	}
}

void printImportTable(){
	printf("IMPORT TABLE\n============\n");

	int dir_num = imp_table->Size / IMAGE_SIZEOF_IMPORT_DESCRIPTOR - 1; // last one is 0's
	for(int i = 0; i < dir_num; i++){
		IMAGE_IMPORT_DESCRIPTOR* imp_desc = 
			(IMAGE_IMPORT_DESCRIPTOR*) &memblock[convertRVAtoPA(imp_table->VirtualAddress) + i*IMAGE_SIZEOF_IMPORT_DESCRIPTOR];

		printf("    IMPORT DIRECTORY\n    ================\n");
		indent_level = 2;

		sprintf_s(msg," (phys: %08X)", convertRVAtoPA(imp_desc->OriginalFirstThunk));
		printLine("Import Name Table RVA", imp_desc->OriginalFirstThunk, FORMAT_DWORD, msg);
		printLine("Time Date Stamp", imp_desc->TimeDateStamp , FORMAT_DWORD);
		printLine("Forwarder Chain", imp_desc->ForwarderChain, FORMAT_DWORD);

		sprintf_s(msg," (phys: %08X) --> %s", convertRVAtoPA(imp_desc->Name), &memblock[convertRVAtoPA(imp_desc->Name)]);
		printLine("Name", imp_desc->Name , FORMAT_DWORD, msg);

		sprintf_s(msg," (phys: %08X)", convertRVAtoPA(imp_desc->FirstThunk));
		printLine("Import Address Table RVA", imp_desc->FirstThunk, FORMAT_DWORD, msg);

		// ITERATE OVER THUNKS - API ENTRIES
		printf("\n        IMPORT THUNKS\n        =============\n");
		indent_level = 3;

		IMAGE_THUNK_DATA32* thunk_data = (IMAGE_THUNK_DATA32*)&memblock[convertRVAtoPA(imp_desc->OriginalFirstThunk)];

		while(thunk_data->u1.AddressOfData != NULL){
			if(thunk_data->u1.Ordinal & ORDINAL_FLAG_32){	// ordinal
				
			}else{
				int api_pa = convertRVAtoPA(thunk_data->u1.AddressOfData);
				IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)&memblock[api_pa];
				sprintf_s(msg," (phys: %08X) --> Hint: %04X, Name: %s", &memblock[api_pa], ibn->Hint,&ibn->Name);
				printLine("API (Function Name)", thunk_data->u1.AddressOfData,FORMAT_DWORD, msg);
			}


			thunk_data++;
		}
		printf("\n");

		indent_level = 1;

	}
}

// Reverse index and values
WORD* reverseOrdinalTable(WORD* ord_table, int size){
	WORD* rev_ord_table = new WORD[size];
	for(int i = 0; i < size; i++){
		rev_ord_table[ ord_table[i] ] = i;
	}

	return rev_ord_table;
}

void printExportTable(){

	printf("EXPORT TABLE\n============\n");

	printf("    EXPORT DIRECTORY\n    ================\n");
	indent_level = 2;
	
	IMAGE_EXPORT_DIRECTORY* exp_dir = 
			(IMAGE_EXPORT_DIRECTORY*) &memblock[convertRVAtoPA(exp_table->VirtualAddress)];

	printLine("Characteristics", exp_dir->Characteristics, FORMAT_DWORD);
	printLine("Time Date Stamp", exp_dir->TimeDateStamp, FORMAT_DWORD);
	printLine("Major Version", exp_dir->MajorVersion, FORMAT_WORD);
	printLine("Minor Version", exp_dir->MinorVersion, FORMAT_WORD);

	sprintf_s(msg," (phys: %08X) --> %s", convertRVAtoPA(exp_dir->Name), &memblock[convertRVAtoPA(exp_dir->Name)]);
	printLine("Name RVA", exp_dir->Name, FORMAT_DWORD, msg);

	printLine("Ordinal Base", exp_dir->Base, FORMAT_DWORD);
	printLine("Number of Functions", exp_dir->NumberOfFunctions, FORMAT_DWORD);
	printLine("Number of Names", exp_dir->NumberOfNames, FORMAT_DWORD);

	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(exp_dir->AddressOfFunctions));
	printLine("Address Table RVA", exp_dir->AddressOfFunctions, FORMAT_DWORD, msg);
	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(exp_dir->AddressOfNames));
	printLine("Name Pointer Table RVA", exp_dir->AddressOfNames, FORMAT_DWORD, msg);
	sprintf_s(msg," (phys: %08X)", convertRVAtoPA(exp_dir->AddressOfNameOrdinals));
	printLine("Ordinal Table RVA", exp_dir->AddressOfNameOrdinals, FORMAT_DWORD, msg);
	printf("\n");

	// BIND EXPORT DIRECTORY TABLE POINTERS
	DWORD* addr_table = (DWORD*)&memblock[convertRVAtoPA(exp_dir->AddressOfFunctions)];
	DWORD* name_table = (DWORD*)&memblock[convertRVAtoPA(exp_dir->AddressOfNames)];
	WORD* ord_table = (WORD*)&memblock[convertRVAtoPA(exp_dir->AddressOfNameOrdinals)];
	WORD* rev_ord_table = reverseOrdinalTable(ord_table, exp_dir->NumberOfNames);

	indent_level = 3;
	printf("        Export address table\n"
           "        ====================\n");
	
	for(unsigned int i = 0; i < exp_dir->NumberOfFunctions; i++){
		int fun_addr = *(addr_table + i);
		if(fun_addr >= exp_table->VirtualAddress
			&& fun_addr < exp_table->VirtualAddress + exp_table->Size){ // Forwarder RVA

			sprintf_s(msg," (phys: %08X) --> Ordinal: %04X, Name: %s --> %s", 
				convertRVAtoPA(fun_addr),
				rev_ord_table[ord_table[i]] + exp_dir->Base,
				(char*) &memblock[convertRVAtoPA(name_table[i])],
				(char*) &memblock[convertRVAtoPA(fun_addr)]
				);
			printLine("API (Function Name Forwarder RVA)", fun_addr, FORMAT_DWORD, msg);
			

		}else{	// function is exported as RVA
			sprintf_s(msg," (phys: %08X) --> Ordinal: %04X, Name: %s", 
				convertRVAtoPA(fun_addr),
				rev_ord_table[ord_table[i]] + exp_dir->Base,
				(char*) &memblock[convertRVAtoPA(name_table[rev_ord_table[i]])]				
				);
			printLine("API (Function Address RVA)", fun_addr, FORMAT_DWORD, msg);
		}
		
	}
	printf("\n");

	printf("        Export function name table\n"
           "        ==========================\n");
	for(unsigned int i = 0; i < exp_dir->NumberOfNames; i++){
		int name_addr = name_table[i];
		sprintf_s(msg," (phys: %08X) --> Ordinal: %04X, Name: %s", 
				convertRVAtoPA(name_addr),
				ord_table[i] + exp_dir->Base,
				(char*) &memblock[convertRVAtoPA(name_table[i])]				
				);
		printLine("API (Function Name RVA)", name_addr, FORMAT_DWORD, msg);
		
	}
	printf("\n");

	printf("        Export ordinal table\n"
           "        ====================\n");
	for(unsigned int i = 0; i < exp_dir->NumberOfNames; i++){
		int ord_addr = ord_table[i];
		sprintf_s(msg," --> Decoded Ordinal: %04X, Name: %s",
				ord_table[i] + exp_dir->Base,
				(char*) &memblock[convertRVAtoPA(name_table[i])]				
				);
		printLine("API (Ordinal Value)", ord_addr, FORMAT_WORD, msg);
		
	}

	printf("\n");
}

void printParsedFile(){
	printMZHeader();
	printPEHeader();
	printSectionHeaders();
	printImportTable();

	if(exp_table->VirtualAddress > 0){
		printExportTable();
	}
}


int main (int argc, char* argv[]) {
	if(argc != 2){
		cout << "Usage: PEParser <path_to_exe_file" << endl;
	}

	// READ FILE INTO BUFFER
	streampos size;
	ifstream file (argv[1], ios::in|ios::binary|ios::ate);
	if (file.is_open()){

		size = file.tellg();
		memblock = new char [size];
		file.seekg (0, ios::beg);

		file.read ((char*)memblock, size);

		file.close();

	}else{
		cout << "Unable to open file";
		exit(0);
	}

	// MZ HEADER
	dos_header = (IMAGE_DOS_HEADER*)memblock;
	
	// PE HEADER
	pe_header = (IMAGE_NT_HEADERS32*)&memblock[dos_header->e_lfanew];
	file_header = &pe_header->FileHeader;
	opt_header = &pe_header->OptionalHeader;

	// SECTION HEADERS
	
	int sec_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	sec_headers = (IMAGE_SECTION_HEADER*)&memblock[sec_offset];

	
	if( opt_header->Magic != 0x010b ){
		printf("PEParser supports only 32-bit files");
		exit(0);
	}

	printParsedFile();

	// cleanup
	delete[] memblock;

	return 0;
}