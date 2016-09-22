using System;
using Microsoft.Azure.Web.DataProtection;
using Microsoft.AspNetCore.DataProtection;
using Xunit;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Azure.Web.DataProtection.Tests
{
    public class DefaultEncryptionKeyResolverTests
    {
        [Fact]
        public void GetAllKeys_WithNoKeysSet_ReturnsDefaultKey()
        {
            var resolver = new DefaultEncryptionKeyResolver();
            string keyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";

            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, keyValue))
            {
                IReadOnlyCollection<CryptographicKey> keys = resolver.GetAllKeys();

                Assert.Equal(1, keys.Count);
                Assert.Equal(Guid.Empty.ToString(), keys.First().Id);
                Assert.Equal(CryptoUtil.ConvertHexToByteArray(keyValue), keys.First().Value);
            }
        }

        [Fact]
        public void GetAllKeys_WithPrimaryKeySet_PrioritizesPrimaryKey()
        {
            var resolver = new DefaultEncryptionKeyResolver();

            string keyId = "ae67b5ee-aa29-44a4-85ac-fc7137cb44ce";
            string keyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            var environmentVariables = new Dictionary<string, string>
            {
                { Constants.AzureWebsitePrimaryEncryptionKeyId,   keyId},
                { $"AzureWebEncryptionKey_{keyId}", keyValue },

            };

            using (var variables = new TestScopedEnvironmentVariable(environmentVariables))
            {
                IReadOnlyCollection<CryptographicKey> keys = resolver.GetAllKeys();

                Assert.Equal(2, keys.Count);
                Assert.Equal(keyId, keys.First().Id);
                Assert.Equal(CryptoUtil.ConvertHexToByteArray(keyValue), keys.First().Value);
                
                // Default key is included
                Assert.Equal(Guid.Empty.ToString(), keys.Skip(1).First().Id);
            }
        }

        [Fact]
        public void GetAllKeys_WithPrimaryAndSecondaryKeysSet_ReturnsExpectedKeys()
        {
            var resolver = new DefaultEncryptionKeyResolver();

            string primakeyId = "ae67b5ee-aa29-44a4-85ac-fc7137cb44ce";
            string primaryKeyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            string secondaryId = "be67b5ee-aa29-44a4-85ac-fc7137cb44ce";
            string secondaryKeyValue = "1F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            var environmentVariables = new Dictionary<string, string>
            {
                { Constants.AzureWebsitePrimaryEncryptionKeyId,   primakeyId},
                { $"AzureWebEncryptionKey_{primakeyId}", primaryKeyValue },
                { Constants.AzureWebsiteSecondaryEncryptionKeyId,   secondaryId},
                { $"AzureWebEncryptionKey_{secondaryId}", secondaryKeyValue }
            };

            using (var variables = new TestScopedEnvironmentVariable(environmentVariables))
            {
                IReadOnlyCollection<CryptographicKey> keys = resolver.GetAllKeys();

                Assert.Equal(2, keys.Count);
                Assert.Equal(primakeyId, keys.First().Id);
                Assert.Equal(CryptoUtil.ConvertHexToByteArray(primaryKeyValue), keys.First().Value);                
                Assert.Equal(secondaryId, keys.Skip(1).First().Id);
                Assert.Equal(CryptoUtil.ConvertHexToByteArray(secondaryKeyValue), keys.Skip(1).First().Value);
            }
        }
    }
}
