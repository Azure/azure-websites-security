// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using Microsoft.Azure.Web.DataProtection;
using Microsoft.Azure.Web.DataProtection.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Azure.WebSites.DataProtection.UnitTests
{
    public class JwtGeneratorTests
    {
        private const string TestKeyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";

        [Fact]
        public void IssuedToken_WithDefaultValidation_SucceedsValidation()
        {
            // There are three separate CodeQL alerts for the same issue. Multiple comments on same line is intentional.
            // CodeQL [SM04387] this handler does not verify AAD tokens. It verifies tokens issued by the platform. // CodeQL [SM03926] this handler does not verify AAD tokens. It verifies tokens issued by the platform. // CodeQL [SM04284] this handler does not verify AAD tokens. It verifies tokens issued by the platform.
            var testParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestKeyValue)),
                ValidateIssuer = false,
                ValidateAudience = false
            };

            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, TestKeyValue))
            {
                var token = JwtGenerator.GenerateToken("testissuer", "testaudience");

                bool result = JwtGenerator.IsTokenValid(token, testParameters);

                Assert.True(result);
            }
        }

        [Fact]
        public void IssuedToken_WithInvalidValues_FailsValidation()
        {
            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, TestKeyValue))
            {
                var token = JwtGenerator.GenerateToken("testissuer", "testaudience");

                // There are two separate CodeQL alerts for the same issue. The double comment on same line is intentional.
                // CodeQL [SM04555] this handler does not verify AAD tokens. It verifies tokens issued by the platform. // CodeQL [SM04554] this handler does not verify AAD tokens. It verifies tokens issued by the platform.
                var testParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestKeyValue)),
                    ValidateIssuer = true,
                    ValidateAudience = true
                };

                bool result = JwtGenerator.IsTokenValid(token, testParameters);

                Assert.False(result);
            }
        }

        [Fact]
        public void GeneratedToken_ContainsExpectedClaims()
        {
            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, TestKeyValue))
            {
                var issuer = "testissuer";
                var audience = "testaudience";
                var expiration = new DateTime(2017, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var notBefore = expiration.AddSeconds(-10);

                var token = JwtGenerator.GenerateToken(issuer, audience, notBefore, expiration);

                var jwt = new JwtSecurityToken(token);

                Assert.Equal(issuer, jwt.Issuer);
                Assert.Equal(audience, jwt.Audiences.First());
                Assert.Equal(expiration, jwt.ValidTo);
                Assert.Equal(notBefore, jwt.ValidFrom);
            }
        }
    }
}
