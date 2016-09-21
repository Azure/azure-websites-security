// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Azure.Web.Cryptography
{
    /// <summary>
    /// Provides encryption and decryption services using the Advanced Encryption Standard (AES) algorithm.
    /// The default <see cref="IEncryptionKeyResolver"/> used by this class provides resolution logic optimized
    /// to work in the Azure App Service environments (e.g. Azure Web Apps, Azure Functions and WebJobs), with key
    /// rolling support.
    /// </summary>
    public class CryptoService
    {
        private readonly IEncryptionKeyResolver _keyResolver;

        public CryptoService()
            : this(new DefaultEncryptionKeyResolver())
        {
        }

        public CryptoService(IEncryptionKeyResolver keyResolver)
        {
            if (keyResolver == null)
            {
                throw new ArgumentNullException(nameof(keyResolver));
            }

            _keyResolver = keyResolver;
        }

        public EncryptionResult<string> EncryptValue(string value, string keyId = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            CryptographicKey cryptoKey = GetEncryptionKey(keyId);

            byte[] data = Encoding.UTF8.GetBytes(value);
            byte[] encryptedData = EncryptData(data, cryptoKey.GetValue());
            string encryptedValue = Convert.ToBase64String(encryptedData);

            return new EncryptionResult<string>(cryptoKey.Id, encryptedValue);
        }

        public EncryptionResult<byte[]> EncryptValue(byte[] value, string keyId = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            CryptographicKey cryptoKey = GetEncryptionKey(keyId);
            byte[] encryptedData = EncryptData(value, cryptoKey.GetValue());

            return new EncryptionResult<byte[]>(cryptoKey.Id, encryptedData);
        }

        public byte[] DecryptValue(byte[] value, string keyId = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            CryptographicKey cryptoKey = GetEncryptionKey(keyId);

            return DecryptData(value, cryptoKey.GetValue());
        }

        public string DecryptValue(string value, string keyId = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            byte[] encryptedData = Convert.FromBase64String(value);
            byte[] result = DecryptValue(encryptedData, keyId);

            return Encoding.UTF8.GetString(result);
        }

        private CryptographicKey GetEncryptionKey(string keyId, bool throwIfNotFound = true)
        {
            CryptographicKey cryptoKey = _keyResolver.ResolveKey(keyId);

            if (throwIfNotFound && cryptoKey == null)
            {
                throw new CryptographicException($"Missing key configuration. (Key id: {keyId})");
            }

            return cryptoKey;
        }

        private static byte[] EncryptData(byte[] value, byte[] encryptionKey)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = encryptionKey;
                aes.GenerateIV();

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (var resultStream = new MemoryStream())
                {
                    // Write the IV to the stream (IV will prepend the encrypted data)
                    resultStream.Write(aes.IV, 0, aes.IV.Length);

                    using (var cryptoStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var writer = new BinaryWriter(cryptoStream))
                        {
                            writer.Write(value);
                        }

                        return resultStream.ToArray();
                    }
                }
            }
        }

        private static byte[] DecryptData(byte[] encryptedData, byte[] encryptionKey)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = encryptionKey;

                int blockSizeInBytes = aes.BlockSize / 8;
                byte[] iv = encryptedData.Take(blockSizeInBytes).ToArray();

                ICryptoTransform decryptor = aes.CreateDecryptor(encryptionKey, iv);

                using (var stream = new MemoryStream(encryptedData, blockSizeInBytes, encryptedData.Length - blockSizeInBytes))
                {
                    using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var reader = new BinaryReader(cryptoStream))
                        {
                            return reader.ReadBytes(encryptedData.Length);
                        }
                    }
                }
            }
        }
    }
}
