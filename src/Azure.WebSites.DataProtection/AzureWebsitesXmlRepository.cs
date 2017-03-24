// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Repositories;
using static Microsoft.Azure.Web.DataProtection.Constants;
using static Microsoft.Azure.Web.DataProtection.Util;

namespace Microsoft.Azure.Web.DataProtection
{
    public class AzureWebsitesXmlRepository : IXmlRepository
    {
        internal static readonly XName KeyElementName = "key";
        internal static readonly XName IdAttributeName = "id";
        internal static readonly XName VersionAttributeName = "version";
        internal static readonly XName CreationDateElementName = "creationDate";
        internal static readonly XName ActivationDateElementName = "activationDate";
        internal static readonly XName ExpirationDateElementName = "expirationDate";
        internal static readonly XName DescriptorElementName = "descriptor";
        internal static readonly XName DeserializerTypeAttributeName = "deserializerType";
        private static readonly Regex KeySettingNameRegex = new Regex($"^{AzureWebReferencedKeyPrefix}(?<keyid>[0-9A-Fa-f]{{8}}[-]([0-9A-Fa-f]{{4}}-){{3}}[0-9A-Fa-f]{{12}})$");

        private readonly AuthenticatedEncryptorConfiguration _encryptorConfiguration;

        public AzureWebsitesXmlRepository(IAuthenticatedEncryptorConfiguration encryptorConfiguration)
        {
            _encryptorConfiguration = encryptorConfiguration as AuthenticatedEncryptorConfiguration;
        }
 
        public void StoreElement(XElement element, string friendlyName)
        {
            throw new NotSupportedException();
        }
     
        public byte[] ResolveKey(Guid keyId)
        {
            string keyValue = IsDefaultKey(keyId) ? GetDefaultKeyValue() : GetEnvironmentKey(keyId);

            if (keyValue != null)
            {
                return ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            var keys = new List<CryptographicKey>();

            CryptographicKey primaryKey = GetReferencedKey(AzureWebsitePrimaryEncryptionKeyId);

            if (primaryKey != null)
            {
                keys.Add(primaryKey);
            }

            // Add our default key. If a primary key is not specified, this implicitly becomes
            // the primary (default) key.
            byte[] defaultKeyValue = GetDefaultKey();
            if (defaultKeyValue != null)
            {
                var defaultKey = new CryptographicKey(DefaultKeyId, defaultKeyValue);
                keys.Add(defaultKey);
            }

            // Get other defined keys
            var definedKeys = Environment.GetEnvironmentVariables();

            foreach (var key in definedKeys.Keys)
            {
                Guid keyId;
                Match match = KeySettingNameRegex.Match(key.ToString());
                if (match.Success && Guid.TryParse(match.Groups["keyid"].Value, out keyId) && !keys.Any(k => k.Id == keyId))
                {
                    byte[] value = Util.ConvertHexToByteArray(definedKeys[key].ToString());

                    var cryptoKey = new CryptographicKey(keyId, value);

                    keys.Add(cryptoKey);
                }
            }

            return keys.Select((k, i) => CreateKeyElement(k, i))
                .ToList()
                .AsReadOnly();
        }

        private XElement CreateKeyElement(CryptographicKey k, int position)
        {
            var newDescriptor = new AuthenticatedEncryptorDescriptor(_encryptorConfiguration.Settings, new Secret(k.Value));
            var descriptor = newDescriptor.ExportToXml();
  
            return new XElement(KeyElementName,
                new XAttribute(IdAttributeName, k.Id), 
                new XAttribute(VersionAttributeName, 1),
                new XElement(CreationDateElementName, DateTimeOffset.UtcNow.AddMinutes(-position)),
                new XElement(ActivationDateElementName, DateTimeOffset.UtcNow.AddMinutes(-position)),
                new XElement(ExpirationDateElementName, DateTimeOffset.UtcNow.AddYears(10)),
                new XElement(DescriptorElementName,
                    new XAttribute(DeserializerTypeAttributeName, descriptor.DeserializerType.AssemblyQualifiedName), 
                    descriptor.SerializedDescriptorElement));
        }

        private CryptographicKey GetReferencedKey(string reference)
        {
            try
            {
                Guid keyId;
                if (Guid.TryParse(Environment.GetEnvironmentVariable(reference), out keyId))
                {
                    string value = Environment.GetEnvironmentVariable(GetKeySettingName(keyId));

                    if (!string.IsNullOrEmpty(value))
                    {
                        return new CryptographicKey(keyId, ConvertHexToByteArray(value));
                    }
                }
            }
            catch { }

            return null;
        }

        private byte[] GetDefaultKey()
        {
            string keyValue = GetDefaultKeyValue();

            if (keyValue != null)
            {
                return ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        private string GetEnvironmentKey(Guid keyId) => Environment.GetEnvironmentVariable(GetKeySettingName(keyId));

        private string GetKeySettingName(Guid keyId) => $"{AzureWebReferencedKeyPrefix}{keyId}";
    }
}
