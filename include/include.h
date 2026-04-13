#pragma once 
#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#include "Native.h"
#include "beacon.h"

// BOFPatcher
#define CAPI(func_name) __declspec(dllimport) __typeof(func_name) func_name;
CAPI(NtOpenKeyEx)
CAPI(RtlInitUnicodeString)
CAPI(NtEnumerateKey)
CAPI(calloc)
CAPI(NtQueryKey)
CAPI(free)
CAPI(wcsstr)
CAPI(swprintf)
CAPI(wcstoul)
CAPI(NtClose)
CAPI(BCryptCloseAlgorithmProvider)
CAPI(BCryptDecrypt)
CAPI(BCryptDestroyKey)
CAPI(BCryptGenerateSymmetricKey)
CAPI(BCryptOpenAlgorithmProvider)
CAPI(BCryptSetProperty)
CAPI(BCryptCreateHash)
CAPI(BCryptDestroyHash)
CAPI(BCryptFinishHash)
CAPI(BCryptGetProperty)
CAPI(BCryptHashData)
CAPI(NtEnumerateValueKey)
CAPI(memcmp)
CAPI(wcslen)

// Globals
EXTERN_C formatp pOutBuf;
EXTERN_C formatp pHashcatBuf;
EXTERN_C BOOL    bHashcatOut;
EXTERN_C UCHAR   BootKey[16];
EXTERN_C UCHAR   EncBootKey[16];
EXTERN_C SIZE_T  szKfi;    
EXTERN_C SIZE_T  szKbi;
EXTERN_C SIZE_T  szKvbi;

// Common funcs
VOID SizeAndFreeBuffer(PPVOID pBuffer);

// Mimikatz defs
// https://github.com/rapid7/mimikatz/blob/a82208ee934c39706e4e93db16e77cb55bd35f36/inc/globals.h#L137
// https://github.com/rapid7/mimikatz/blob/master/modules/kull_m_crypto_system.h#L12
#define SHA_DIGEST_LENGTH	20
#define LAZY_NT6_IV_SIZE	32
#define LAZY_IV_SIZE	16
#define	MD5_DIGEST_LENGTH	16
#define LM_NTLM_HASH_LENGTH	16
#define SIZE_ALIGN(size, alignment)	(size + ((size % alignment) ? (alignment - (size % alignment)) : 0))

// Def for additional BCRYPT mode
#ifndef BCRYPT_CHAIN_MODE_CTS
#define BCRYPT_CHAIN_MODE_CTS L"ChainingModeCTS"
#endif

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )

//
// Pointer arithmetic macros 
//

// These determine the number of arguments passed
#define NARGS_IMPL(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define NARGS(...) NARGS_IMPL(__VA_ARGS__,10,9,8,7,6,5,4,3,2,1,0)

// Helpers
#define CONCAT(a,b) a##b
#define EXPAND_AND_CONCAT(a,b) CONCAT(a,b)

// Addition macros
#define ADD1(a) U_PTR(a)
#define ADD2(a,b) U_PTR(a) + U_PTR(b)
#define ADD3(a,b,c) U_PTR(a) + U_PTR(b) + U_PTR(c)
#define ADD4(a,b,c,d) U_PTR(a) + U_PTR(b) + U_PTR(c) + U_PTR(d)
#define ADD5(a,b,c,d,e) U_PTR(a) + U_PTR(b) + U_PTR(c) + U_PTR(d) + U_PTR(e)
#define ADD6(a,b,c,d,e,f) ADD5(a,b,c,d,e) + U_PTR(f)
#define ADD7(a,b,c,d,e,f,g) ADD6(a,b,c,d,e,f) + U_PTR(g)
#define ADD8(a,b,c,d,e,f,g,h) ADD7(a,b,c,d,e,f,g) + U_PTR(h)
#define ADD9(a,b,c,d,e,f,g,h,i) ADD8(a,b,c,d,e,f,g,h) + U_PTR(i)
#define ADD10(a,b,c,d,e,f,g,h,i,j) ADD9(a,b,c,d,e,f,g,h,i) + U_PTR(j)
#define ADD_DISPATCH(N, ...) EXPAND_AND_CONCAT(ADD, N)(__VA_ARGS__)
#define PADD(...) ((PVOID)(ADD_DISPATCH(NARGS(__VA_ARGS__), __VA_ARGS__)))

// Subtraction macros
#define SUB1(a) U_PTR(a)
#define SUB2(a,b) U_PTR(a) - U_PTR(b)
#define SUB3(a,b,c) SUB2(a,b) - U_PTR(c)
#define SUB4(a,b,c,d) SUB3(a,b,c) - U_PTR(d)
#define SUB5(a,b,c,d,e) SUB4(a,b,c,d) - U_PTR(e)
#define SUB6(a,b,c,d,e,f) SUB5(a,b,c,d,e) - U_PTR(f)
#define SUB7(a,b,c,d,e,f,g) SUB6(a,b,c,d,e,f) - U_PTR(g)
#define SUB8(a,b,c,d,e,f,g,h) SUB7(a,b,c,d,e,f,g) - U_PTR(h)
#define SUB9(a,b,c,d,e,f,g,h,i) SUB8(a,b,c,d,e,f,g,h) - U_PTR(i)
#define SUB10(a,b,c,d,e,f,g,h,i,j) SUB9(a,b,c,d,e,f,g,h,i) - U_PTR(j)
#define SUB_DISPATCH(N, ...) EXPAND_AND_CONCAT(SUB, N)(__VA_ARGS__)
#define PSUB(...) ((PVOID)(SUB_DISPATCH(NARGS(__VA_ARGS__), __VA_ARGS__)))

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG         TitleIndex;
  ULONG         ClassOffset;
  ULONG         ClassLength;
  ULONG         NameLength;
  WCHAR         Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

// https://github.com/rescatux/chntpw/blob/master/sam.h#L139
/* Users V data struct */
/* First 0xCC bytes is pointer & len table, rest is data which
 * the table points to
 * String data is unicode, not zero terminated (must use len)
 */
typedef struct _USER_V {

  int unknown1_1;      /* 0x00 - always zero? */
  int unknown1_2;      /* 0x04 - points to username? */
  int unknown1_3;      /* 0x08 - always 0x02 0x00 0x01 0x00 ? */
  int username_ofs;    /* 0x0c */
  int username_len;    /* 0x10 */
  int unknown2_1;      /* 0x14 - always zero? */
  int fullname_ofs;    /* 0x18 */
  int fullname_len;    /* 0x1c */
  int unknown3_1;      /* 0x20 - always zero? */
  int comment_ofs;     /* 0x24 */
  int comment_len;     /* 0x28 */
  int unknown4_1;      /* 0x2c - alway zero? */
  int unknown4_2;      /* 0x30 - points 4 or 8 byte field before hashes */
  int unknown4_3;      /* 0x34 - zero? or size? */
  int unknown4_4;      /* 0x38 - zero? */
  int unknown4_5;      /* 0x3c - to field 8 bytes before hashes */
  int unknown4_6;      /* 0x40 - zero? or size of above? */
  int unknown4_7;      /* 0x44 - zero? */
  int homedir_ofs;     /* 0x48 */
  int homedir_len;     /* 0x4c */
  int unknown5_1;      /* 0x50 - zero? */
  int drvletter_ofs;   /* 0x54 - drive letter for home dir */
  int drvletter_len;   /* 0x58 - len of above, usually 4   */
  int unknown6_1;      /* 0x5c - zero? */
  int logonscr_ofs;    /* 0x60 - users logon script path */
  int logonscr_len;    /* 0x64 - length of string */
  int unknown7_1;      /* 0x68 - zero? */
  int profilep_ofs;    /* 0x6c - profile path string */
  int profilep_len;    /* 0x70 - profile path stringlen */
  char unknown7[0x90-0x74]; /* 0x74 */
  int unknown8_1;      /* 0x90 - pointer to some place before hashes, after comments */
  int unknown8_2;      /* 0x94 - size of above? */
  int unknown8_3;      /* 0x98 - unknown? always 1? */
  int lmpw_ofs;        /* 0x9c */
  int lmpw_len;        /* 0xa0 */
  int unknown9_1;      /* 0xa4 - zero? */
  int ntpw_ofs;        /* 0xa8 */
  int ntpw_len;        /* 0xac */
  int unknowna_1;      /* 0xb0 */
  int unknowna_2;      /* 0xb4 - points to field after hashes */
  int unknowna_3;      /* 0xb8 - size of above field */
  int unknowna_4;      /* 0xbc - zero? */
  int unknowna_5;      /* 0xc0 - points to field after that */
  int unknowna_6;      /* 0xc4 - size of above */
  int unknowna_7;      /* 0xc8 - zero ? */
  char data[4];        /* Data starts here. All pointers above is relative to this,
			  that is V + 0xCC */
} USER_V, *PUSER_V;

// https://github.com/j0urney1/RemoteSamDecrypt/blob/769723b83ac69f5030d679fc7ae10e473f62fc51/RemoteSamDecrypt/reg.h
typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG HighPart;
} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

typedef enum _DOMAIN_SERVER_ENABLE_STATE
{
	DomainServerEnabled = 1,
	DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, *PDOMAIN_SERVER_ENABLE_STATE;

typedef  enum _DOMAIN_SERVER_ROLE
{
	DomainServerRoleBackup = 2,
	DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, *PDOMAIN_SERVER_ROLE;

typedef struct _SAM_KEY_DATA {
	DWORD Revision;
	DWORD Length;
	BYTE Salt[0x10];
	BYTE Key[0x10];
	BYTE CheckSum[0x10];
	DWORD unk0;
	DWORD unk1;
} SAM_KEY_DATA, *PSAM_KEY_DATA;

// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/kuhl_m_lsadump.h#L139
typedef struct _SAM_KEY_DATA_AES {
	DWORD Revision; // 2
	DWORD Length;
	DWORD CheckLen;
	DWORD DataLen;
	BYTE Salt[0x10];
	BYTE data[ANYSIZE_ARRAY]; // Data, then Check
} SAM_KEY_DATA_AES, *PSAM_KEY_DATA_AES;

typedef struct _SAM_HASH_AES {
	WORD PEKID;
	WORD Revision;
	DWORD dataOffset;
	BYTE Salt[0x10];
	BYTE data[ANYSIZE_ARRAY]; // Data
} SAM_HASH_AES, *PSAM_HASH_AES;

typedef struct _SAM_HASH {
	WORD PEKID;
	WORD Revision;
	BYTE data[ANYSIZE_ARRAY];
} SAM_HASH, *PSAM_HASH;

// https://github.com/j0urney1/RemoteSamDecrypt/blob/769723b83ac69f5030d679fc7ae10e473f62fc51/RemoteSamDecrypt/reg.h
typedef struct _DOMAIN_ACCOUNT_F {
	WORD Revision;
	WORD unk0;
	DWORD unk1;
	OLD_LARGE_INTEGER CreationTime;
	OLD_LARGE_INTEGER DomainModifiedCount;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
	OLD_LARGE_INTEGER ForceLogoff;
	OLD_LARGE_INTEGER LockoutDuration;
	OLD_LARGE_INTEGER LockoutObservationWindow;
	OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
	DWORD NextRid;
	DWORD PasswordProperties;
	WORD MinPasswordLength;
	WORD PasswordHistoryLength;
	WORD LockoutThreshold;
	DOMAIN_SERVER_ENABLE_STATE ServerState;
	DOMAIN_SERVER_ROLE ServerRole;
	BOOL UasCompatibilityRequired;
	DWORD unk2;
	SAM_KEY_DATA keys1;
	SAM_KEY_DATA keys2;
	DWORD unk3;
	DWORD unk4;
} DOMAIN_ACCOUNT_F, *PDOMAIN_ACCOUNT_F;

// https://github.com/Adaptix-Framework/Extension-Kit/blob/9413caf85fd83272f5866ef42f9e7ed8db9987d6/Creds-BOF/hashdump/hashdump.c#L7
const BYTE ODD_PARITY[] = {
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254 };

// https://github.com/rapid7/mimikatz/blob/a82208ee934c39706e4e93db16e77cb55bd35f36/mimikatz/modules/kuhl_m_lsadump.h#L215
typedef struct _NT6_CLEAR_SECRET {
	DWORD SecretSize;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *PNT6_CLEAR_SECRET;

typedef struct _NT6_HARD_SECRET {
	DWORD version;
	GUID KeyId;
	DWORD algorithm;
	DWORD flag;
	BYTE lazyiv[LAZY_NT6_IV_SIZE];
	union {
		NT6_CLEAR_SECRET clearSecret;
		BYTE encryptedSecret[ANYSIZE_ARRAY];
	};
} NT6_HARD_SECRET, *PNT6_HARD_SECRET;

typedef struct _NT6_SYSTEM_KEY {
	GUID KeyId;
	DWORD KeyType;
	DWORD KeySize;
	BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *PNT6_SYSTEM_KEY;

typedef struct _NT6_SYSTEM_KEYS {
	DWORD unkType0;
	GUID CurrentKeyID;
	DWORD unkType1;
	DWORD nbKeys;
	NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *PNT6_SYSTEM_KEYS;

typedef struct _MSCACHE_ENTRY {
	WORD szUserName;
	WORD szDomainName;
	WORD szEffectiveName;
	WORD szFullName;
	WORD szlogonScript;
	WORD szprofilePath;
	WORD szhomeDirectory;
	WORD szhomeDirectoryDrive;
	DWORD userId;
	DWORD primaryGroupId;
	DWORD groupCount;
	WORD szlogonDomainName;
	WORD unk0;
	FILETIME lastWrite;
	DWORD revision;
	DWORD sidCount;
	DWORD flags;
	DWORD unk1;
	DWORD logonPackage;
	WORD szDnsDomainName;
	WORD szupn;
	BYTE iv[LAZY_IV_SIZE];
	BYTE cksum[MD5_DIGEST_LENGTH];
	BYTE enc_data[ANYSIZE_ARRAY];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;

typedef struct _GROUP_MEMBERSHIP {
	DWORD RelativeId;
	DWORD Attributes;
} GROUP_MEMBERSHIP, *PGROUP_MEMBERSHIP;

typedef struct _MSCACHE_ENTRY_PTR {
	UNICODE_STRING UserName;
	UNICODE_STRING Domain;
	UNICODE_STRING DnsDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;

	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;

	PGROUP_MEMBERSHIP Groups;

	UNICODE_STRING LogonDomainName;

} MSCACHE_ENTRY_PTR, *PMSCACHE_ENTRY_PTR;

typedef struct _MSCACHE_DATA {
	BYTE mshashdata[LM_NTLM_HASH_LENGTH];
	BYTE unkhash[LM_NTLM_HASH_LENGTH];
	DWORD unk0;
	DWORD szSC;
	DWORD unkLength;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
} MSCACHE_DATA, *PMSCACHE_DATA;