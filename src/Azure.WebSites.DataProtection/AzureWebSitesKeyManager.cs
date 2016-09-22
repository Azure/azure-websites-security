using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Azure.Web.DataProtection
{
    public class AzureWebsitesKeyManager : IKeyManager
    {
        private readonly AuthenticatedEncryptorConfiguration _encryptorConfiguration;
        private readonly IEncryptionKeyResolver _keyResolver;
        private readonly IServiceProvider _services;
        private readonly static DateTimeOffset BaseCreationDateTime = DateTimeOffset.UtcNow.AddYears(-1);
        
        // Default expiration time shorter than MaxValue to account for clock skew calculations.
        private readonly static DateTimeOffset ExpirationTime = DateTimeOffset.MaxValue.AddDays(-1);

        public AzureWebsitesKeyManager(IAuthenticatedEncryptorConfiguration configuration, IServiceProvider services)
        {
            _encryptorConfiguration = configuration as AuthenticatedEncryptorConfiguration;
            if (_encryptorConfiguration == null)
            {
                throw new ArgumentException($"Invalid encryptor configuration type. This key manager requires a {nameof(AuthenticatedEncryptorConfiguration)} instance", nameof(configuration));
            }

            _keyResolver = services.GetService<IEncryptionKeyResolver>() ?? new DefaultEncryptionKeyResolver();

            _services = services;
        }

        public IKey CreateNewKey(DateTimeOffset activationDate, DateTimeOffset expirationDate)
        {
            throw new NotSupportedException($"The '{nameof(AzureWebsitesKeyManager)}' does not support key creation.");
        }

        public IReadOnlyCollection<IKey> GetAllKeys()
        {
            IReadOnlyCollection<CryptographicKey> keys = _keyResolver.GetAllKeys();

            var result = keys.Select((k, i) => new AzureKey(k.Id,
                BaseCreationDateTime.AddYears(-i),
                BaseCreationDateTime.AddYears(-i),
                ExpirationTime,
                new AuthenticatedEncryptorDescriptor(_encryptorConfiguration.Settings, new Secret(k.Value), _services)))
                .ToList();

            return result.AsReadOnly();
        }

        public CancellationToken GetCacheExpirationToken()
        {
            return CancellationToken.None;
        }

        public void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null)
        {
            throw new NotImplementedException();
        }

        public void RevokeKey(Guid keyId, string reason = null)
        {
            throw new NotImplementedException();
        }
    }
}
