// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using static Microsoft.Azure.Web.DataProtection.Constants;

namespace Microsoft.Azure.Web.DataProtection
{
    public class DefaultEncryptionKeyResolver : IEncryptionKeyResolver
    {
        private static Guid DefaultKeyId = Guid.Parse(DefaultEncryptionKeyId);

        public byte[] ResolveKey(Guid keyId)
        {
            string keyValue = IsDefaultKey(keyId) ? GetDefaultKeyValue() : GetEnvironmentKey(keyId);

            if (keyValue != null)
            {
                return CryptoUtil.ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        public IReadOnlyCollection<CryptographicKey> GetAllKeys()
        {
            var keys = new List<CryptographicKey>();

            CryptographicKey primaryKey = GetReferencedKey(AzureWebsitePrimaryEncryptionKeyId);

            if (primaryKey != null)
            {
                keys.Add(primaryKey);

                CryptographicKey secondaryKey = GetReferencedKey(AzureWebsiteSecondaryEncryptionKeyId);

                if (secondaryKey != null)
                {
                    keys.Add(secondaryKey);
                }
            }

            if (keys.Count < 2)
            {
                var defaultKey = new CryptographicKey(DefaultKeyId, GetDefaultKey());

                keys.Add(defaultKey);
            }

            return keys.AsReadOnly();
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
                        return new CryptographicKey(keyId, CryptoUtil.ConvertHexToByteArray(value));
                    }
                }
            }
            catch { }

            return null;
        }

        private string GetEnvironmentKey(Guid keyId) => Environment.GetEnvironmentVariable(GetKeySettingName(keyId));

        private string GetKeySettingName(Guid keyId) => $"{AzureWebReferencedKeyPrefix}{keyId}";

        private byte[] GetDefaultKey()
        {
            string keyValue = GetDefaultKeyValue();

            if (keyValue != null)
            {
                return CryptoUtil.ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        private string GetDefaultKeyValue()
        {
            if (IsAzureEnvironment())
            {
                // If running in Azure, try to pull the key from the environment
                // and fallback to config file if not available
                return GetMachineConfigKey();
            }

            return Environment.GetEnvironmentVariable(AzureWebsiteLocalEncryptionKey);
        }

        private static bool IsAzureEnvironment() => Environment.GetEnvironmentVariable(AzureWebsiteInstanceId) != null;

        private static bool IsDefaultKey(Guid keyId) => DefaultKeyId == keyId;


        private static string GetMachineConfigKey()
        {
#if NET46
            return ((System.Web.Configuration.MachineKeySection)System.Configuration.ConfigurationManager.GetSection("system.web/machineKey")).DecryptionKey;
#elif NETSTANDARD1_3
            //const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";

            return string.Empty;
            //string key = null;
            //if (File.Exists(configPath))
            //{
            //    using (var reader = new StringReader(File.ReadAllText(configPath)))
            //    {
            //        var xdoc = XDocument.Load(reader);

            //        string siteName = Environment.GetEnvironmentVariable(Constants.AzureWebsiteName);
            //        string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

            //        key = ((IEnumerable)xdoc..XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
            //    }
            //}

            //return key;
#endif
        }
    }
}
