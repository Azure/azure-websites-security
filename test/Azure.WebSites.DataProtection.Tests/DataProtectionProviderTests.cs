using System;
using Microsoft.Azure.Web.DataProtection;
using Microsoft.AspNetCore.DataProtection;
using Xunit;

namespace Microsoft.Azure.Web.DataProtection.Tests
{
    public class DataProtectionProviderTests
    {
        [Fact]
        public void EncryptedValue_CanBeDecrypted() 
        {
            var provider = DataProtectionProvider.CreateAzureDataProtector(b => b.WithLocalDevelopmentKeyResolver());

            var protector = provider.CreateProtector("test");

            string expected = "test string";

            string encrypted = protector.Protect(expected);
            
            string result = protector.Unprotect(encrypted);

            Assert.Equal(expected, result);
        }
    }
}
