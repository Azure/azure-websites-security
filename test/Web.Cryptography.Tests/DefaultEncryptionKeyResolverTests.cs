// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Microsoft.Azure.Web.Cryptography.Tests
{
    public class DefaultEncryptionKeyResolverTests
    {
        [Fact]
        public void ResolveKey_WithDefaultKeyInAzure_ResolvesEnvironmentKey()
        {
            string testKey = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            CryptographicKey expectedKey = CryptographicKey.FromHexString(DefaultEncryptionKeyResolver.DefaultEncryptionKeyId, testKey);

            using (var testVariables = new TestScopedEnvironmentVariable(new Dictionary<string, string>
            {
                { Constants.AzureWebsiteInstanceId, "123" },
                { Constants.AzureWebsiteEncryptionKey, testKey },
            }))
            {
                var resolver = new DefaultEncryptionKeyResolver();
                CryptographicKey key = resolver.ResolveKey(null);

                Assert.NotNull(key);
                Assert.Equal(expectedKey.Id, key.Id);
                Assert.Equal(expectedKey.GetValue(), key.GetValue());
            }
        }

        [Fact]
        public void ResolveKey_WithDefaultKeyInAzureMissingVariable_ResolvesMachineKey()
        {
            string testKey = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            string testRootWebConfig =
$@"<configuration>
          <location path=""testsite"">
            <system.web>
              <machineKey validationKey=""NONE"" decryptionKey=""{testKey}"" decryption=""AES"" />
            </system.web>
          </location>
        </configuration>";

            string testConfigFile = Path.Combine(Path.GetTempPath(), $"{ Guid.NewGuid().ToString()}.config");
            try
            {
                File.WriteAllText(testConfigFile, testRootWebConfig);

                CryptographicKey expectedKey = CryptographicKey.FromHexString(DefaultEncryptionKeyResolver.DefaultEncryptionKeyId, testKey);

                using (var testVariables = new TestScopedEnvironmentVariable(new Dictionary<string, string>
                    {
                        { Constants.AzureWebsiteInstanceId, "123" },
                        { Constants.AzureWebsiteName, "testsite" },
                    }))
                {
                    var resolver = new DefaultEncryptionKeyResolver(testConfigFile);
                    CryptographicKey key = resolver.ResolveKey(null);

                    Assert.NotNull(key);
                    Assert.Equal(expectedKey.Id, key.Id);
                    Assert.Equal(expectedKey.GetValue(), key.GetValue());
                }
            }
            finally
            {
                if (File.Exists(testConfigFile))
                {
                    File.Delete(testConfigFile);
                }
            }
        }

        [Fact]
        public void ResolveKey_WithKeyId_ResolvesEnvinronmentKey()
        {
            string testKeyId = "testkey";
            string testKey = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            CryptographicKey expectedKey = CryptographicKey.FromHexString(testKeyId, testKey);

            using (var testVariables = new TestScopedEnvironmentVariable(new Dictionary<string, string>
            {
                { Constants.AzureWebsiteEncryptionKeyId, testKeyId },
                { testKeyId, testKey },
            }))
            {
                var resolver = new DefaultEncryptionKeyResolver();
                CryptographicKey key = resolver.ResolveKey(null);

                Assert.NotNull(key);
                Assert.Equal(expectedKey.Id, key.Id);
                Assert.Equal(expectedKey.GetValue(), key.GetValue());
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void ResolveKey_WithDefaultKeyLocal_ResolvesEnvironmentKey(string keyId)
        {
            string testKey = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            CryptographicKey expectedKey = CryptographicKey.FromHexString(Constants.AzureWebsiteLocalEncryptionKey, testKey);

            using (var testVariables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, testKey))
            {
                var resolver = new DefaultEncryptionKeyResolver();
                CryptographicKey key = resolver.ResolveKey(keyId);

                Assert.NotNull(key);
                Assert.Equal(DefaultEncryptionKeyResolver.DefaultEncryptionKeyId, key.Id);
                Assert.Equal(expectedKey.GetValue(), key.GetValue());
            }
        }
    }
}
