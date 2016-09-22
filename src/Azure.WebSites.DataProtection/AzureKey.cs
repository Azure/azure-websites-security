using System;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Microsoft.Azure.Web.DataProtection
{
    public class AzureKey : IKey
    {
        private readonly Lazy<IAuthenticatedEncryptor> _lazyEncryptor;

        public AzureKey(Guid keyId, DateTimeOffset creationDate, DateTimeOffset activationDate, DateTimeOffset expirationDate, IAuthenticatedEncryptorDescriptor descriptor)
        {
            KeyId = keyId;
            CreationDate = creationDate;
            ActivationDate = activationDate;
            ExpirationDate = expirationDate;

            _lazyEncryptor = new Lazy<IAuthenticatedEncryptor>(() => descriptor.CreateEncryptorInstance());
        }

        public DateTimeOffset ActivationDate { get; }

        public DateTimeOffset CreationDate { get; }

        public DateTimeOffset ExpirationDate { get; }

        public Guid KeyId { get; }

        public bool IsRevoked { get; private set; }

        public IAuthenticatedEncryptor CreateEncryptorInstance() => _lazyEncryptor.Value;

        internal void SetRevoked() => IsRevoked = true;
    }
}
