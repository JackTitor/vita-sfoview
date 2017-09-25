// sfoview by Kapoera

// TODO: Test non-unicode .sfos and files with utf8special type variables

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>

#if defined(_MSC_VER)
#  define NORETURN __declspec(noreturn)
#else
#  define NORETURN __attribute__((noreturn))
#endif

void NORETURN fatal(const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

typedef uint8_t byte;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t i16;
typedef int32_t i32;

typedef struct{
    u32 magic;
    u32 version;
    u32 keysStart;
    u32 dataStart;
    u32 count;
} sfo_header_t;

typedef struct{
    u16 keyOffset;
    u16 dataFormat;
    u32 dataLen;
    u32 dataMaxLen;
    u32 dataOffset;
} sfo_entry_t;

enum {
	integer		= 0x0404,
	utf8		= 0x0204,
	special		= 0x0004
} data_format_t;

#define		SFO_SIGNATURE	0x46535000	// hex code for " PSF"
#define		MAX_COUNT		256			// sanity check
#define		MAX_KEY_SIZE	256
#define		MIN_DATA_SIZE	64

#define 	PROGRAM_FULL_NAME	"SFOView"
#define 	PROGRAM_EXE_NAME	"sfoview"
#define 	PROGRAM_VERSION		"1.0"

#define 	ERROR_EOF			"ERROR: Unexpected end of file\n"
#define 	ERROR_BAD_SIG		"ERROR: Incorrect SFO signature\n"
#define 	ERROR_FILE_OPEN		"ERROR: Couldn't open file\n"
#define 	ERROR_EXCESS_ARG	"ERROR: Too many arguments\n"
#define 	MSG_HELP			PROGRAM_FULL_NAME " " PROGRAM_VERSION "\n"\
								"\n"\
								"Usage: " PROGRAM_EXE_NAME " sfofile         read sfo from disk\n"\
								"       " PROGRAM_EXE_NAME " -               read sfo from stdin\n"\
								"       " PROGRAM_EXE_NAME " [-h|--help]     show this page\n"

static inline int max ( int a, int b ) {
	return ( a > b ) ? a : b;
}

char * fgets0( char * buf, int size, FILE * file ) {
	int ch, i;
	for (i = 0; i < size-1; ++i) {
		ch = fgetc(file);
		if ( ch == 0 || ch == EOF ) break;
		buf[i] = ch;
	}
	buf[i] = 0;
	if (ch == EOF) return NULL;
	return buf;
}

static inline void skip_bytes( FILE * file, int off ) {
	for ( int i = 0; i < off; ++i )
		fgetc(file);
}

//==================================================================================//

void read_sfo_header( sfo_header_t * ptr, FILE * file ) {
	
	if ( fread( ptr, sizeof(*ptr), 1, file ) != 1 )
		fatal(ERROR_EOF);
	
	if (ptr->magic != SFO_SIGNATURE)	
        fatal(ERROR_BAD_SIG);
}

void read_sfo_metadata( sfo_entry_t meta[], size_t count, FILE * file ) {

	if ( fread( meta, sizeof(sfo_entry_t), count, file ) != count )
		fatal(ERROR_EOF);
}

void read_sfo_keys( char * keys[], size_t * bytes_read, const sfo_entry_t meta[], size_t count, FILE * file ) {
	
	*bytes_read = 0;
	char key_buf[MAX_KEY_SIZE];
	
	for ( int i = 0; i < count; ++i ) {
		#ifdef DEBUG
		printf( "keys[%2d]: 0x%08x\n", i, (u32)ftell(file) );
		#endif
		if ( !fgets0( key_buf, MAX_KEY_SIZE, file ) )
			fatal(ERROR_EOF);
		
		size_t key_size = strlen(key_buf) + 1;
		keys[i] = (char*)malloc(key_size);
		memcpy(keys[i], key_buf, key_size);
		
		*bytes_read += key_size;
	}
}

void read_sfo_values( char * values[], const sfo_entry_t meta[], size_t count, FILE * file ) {
	
	for ( int i = 0; i < count; ++i ) {
		#ifdef DEBUG
		printf( "values[%2d]: 0x%08x\n", i, (u32)ftell(file) );
		#endif
		values[i] = malloc( max(meta[i].dataLen, MIN_DATA_SIZE) );
		if ( fread(values[i], 1, meta[i].dataLen, file) != meta[i].dataLen )
			fatal(ERROR_EOF);
		
		skip_bytes(file, meta[i].dataMaxLen - meta[i].dataLen);
	}

}

void stringify_sfo_values( char * values[], const sfo_entry_t meta[], size_t count ) {
	
	for ( int i = 0; i < count; ++i ) {
		
		switch ( meta[i].dataFormat ) {
			case integer: {
				i32 number;
				memcpy( &number, values[i], 4 );
				sprintf( values[i], "%d", number );
				break;
			}
			case utf8: {
				// already a string
				break;
			}
			case special: {
				size_t len;
				if (meta[i].dataLen > 16) {
					sprintf(values[i] + 16, "...");
					len = 16;
				}
				else {
					len = meta[i].dataLen;
				}
				
				byte buf[len];
				memcpy(buf, values[i], len);
				
				for ( int i = 0; i < len; ++i ) {
					sprintf( values[3*i], "%02x ", buf[i] ); 
				}
				
				break;
			}
			default: {
				// invalid type
				sprintf( values[i], "[invalid type]" );
			}
		}
	}
}

void print_sfo_data( char * const keys[], char * const values[], size_t count ) {
	
	for ( int i = 0; i < count; ++i ) {
		printf( "%-20s %s\n", keys[i], values[i] );
	}
}

void release_sfo_data( char * keys[], char * values[], size_t count ) {
	for (int i = 0; i < count; ++i) {
		free(keys[i]);
		keys[i] = 0;
	}
	for (int i = 0; i < count; ++i) {
		free(values[i]);
		values[i] = 0;
	}
}

void parse_sfo_file(FILE * file) {
	
	sfo_header_t header;
	read_sfo_header(&header, file);
	
	sfo_entry_t meta[header.count];
	read_sfo_metadata(meta, header.count, file);
	
	char * keys[header.count];
	size_t keys_total_size;
	read_sfo_keys( keys, &keys_total_size, meta, header.count, file );
	
	#ifdef DEBUG
	printf("Address after reading keys: 0x%08x\nKeys Length: %u\n", (u32)ftell(file), (u32)keys_total_size);
	#endif
	
	skip_bytes(file, keys_total_size * 3 % 4);
	
	char * values[header.count];
	read_sfo_values( values, meta, header.count, file );
	
	stringify_sfo_values( values, meta, header.count );
	
	print_sfo_data( keys, values, header.count );

	release_sfo_data( keys, values, header.count );
}

//==================================================================================//

int main( int argc, char ** argv ) {
	
	//setlocale(LC_ALL, "en_US.utf8");
	
	if ( argc > 2 )
		fatal(ERROR_EXCESS_ARG);
	
	if ( argc == 1 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ) {
		printf(MSG_HELP);
		return 0;
	}
	
	FILE * file;
	
	if ( strcmp( argv[1], "-" ) == 0 )
		file = freopen(NULL, "rb", stdin);		// read from stdin
	else
		file = fopen(argv[1], "rb");			// read from file at argv[1]
	if (!file)
		fatal("ERROR: Couldn't open \"%s\"\n", argv[1]);
	
	parse_sfo_file(file);
	
	fclose(file);

}
