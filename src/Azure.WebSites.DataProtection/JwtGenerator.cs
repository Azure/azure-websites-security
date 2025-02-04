// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Azure.Web.DataProtection;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Azure.Web.DataProtection
{
    public sealed class JwtGenerator
    {
        public static string GenerateToken(string issuer, string audience, DateTime? notBefore = null, DateTime? expires = null, string key = null)
        {
            notBefore = notBefore ?? DateTime.UtcNow;
            expires = expires ?? DateTime.UtcNow.AddMinutes(30);
            key = key ?? Util.GetDefaultKeyValue();

            if (key == null)
            {
                throw new NullReferenceException("A key value was not provided and a default key is not present.");
            }

            var handler = new JwtSecurityTokenHandler();
            
            var claimsIdentity = new ClaimsIdentity();
            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), 
                SecurityAlgorithms.HmacSha256Signature);

            var token = handler.CreateJwtSecurityToken(issuer, audience, subject: claimsIdentity, notBefore: notBefore, expires: expires,
                signingCredentials: signingCredentials);

            return token.RawData;
        }

        public static ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (validationParameters is null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            var handler = new JwtSecurityTokenHandler();

            return handler.ValidateToken(token, validationParameters, out validatedToken);
        }

        public static bool IsTokenValid(string token, TokenValidationParameters validationParameters = null)
        {
            try
            {
                ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return validatedToken != null;
            }
            catch (SecurityTokenValidationException)
            {
                return false;
            }
        }
    }
}
