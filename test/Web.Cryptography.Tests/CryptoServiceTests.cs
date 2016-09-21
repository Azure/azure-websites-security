// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System.Threading.Tasks;
using Moq;
using Xunit;

namespace Microsoft.Azure.Web.DataProtection.Tests
{
    public class CryptoServiceTests
    {
        [Fact]
        public void Decrypt_WithValidData_DecryptsValue()
        {
            string testKey = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";
            string testData = "Test data";

            var mockResolver = new Mock<IEncryptionKeyResolver>();
            mockResolver.Setup(r => r.ResolveKey(It.IsAny<string>()))
                .Returns<string>(s => CryptographicKey.FromHexString(s, testKey));

            var cryptoService = new CryptoService(mockResolver.Object);

            EncryptionResult<string> encryptionResult = cryptoService.EncryptValue(testData, "testid");

            string decryptedResult = cryptoService.DecryptValue(encryptionResult.Value);

            Assert.Equal("Test data", decryptedResult);
        }
    }
}
