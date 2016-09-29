// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

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
            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248"))
            {
                var provider = DataProtectionProvider.CreateAzureDataProtector(null, true);

                var protector = provider.CreateProtector("test");

                string expected = "test string";

                string encrypted = protector.Protect(expected);

                string result = protector.Unprotect(encrypted);

                Assert.Equal(expected, result);
            }
        }
    }
}
