// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using static Microsoft.Azure.Web.DataProtection.Constants;

namespace Microsoft.Azure.Web.DataProtection
{
    public class DefaultEncryptionKeyResolver : IEncryptionKeyResolver
    {
        private static Guid DefaultKeyId = Guid.Parse(DefaultEncryptionKeyId);
        private static readonly Regex _keySettingNameRegex = new Regex($"^{AzureWebReferencedKeyPrefix}(?<keyid>[0-9A-Fa-f]{{8}}[-]([0-9A-Fa-f]{{4}}-){{3}}[0-9A-Fa-f]{{12}})$");

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
            }

            // Add our default key. If a primary key is not specified, this implicitely becomes
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
                Match match = _keySettingNameRegex.Match(key.ToString());
                if (match.Success && Guid.TryParse(match.Groups["keyid"].Value, out keyId) && !keys.Any(k => k.Id == keyId))
                {
                    byte[] value = CryptoUtil.ConvertHexToByteArray(definedKeys[key].ToString());

                    var cryptoKey = new CryptographicKey(keyId, value);

                    keys.Add(cryptoKey);
                }
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

        private byte[] GetDefaultKey()
        {
            string keyValue = GetDefaultKeyValue();

            if (keyValue != null)
            {
                return CryptoUtil.ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        private string GetEnvironmentKey(Guid keyId) => Environment.GetEnvironmentVariable(GetKeySettingName(keyId));

        private string GetKeySettingName(Guid keyId) => $"{AzureWebReferencedKeyPrefix}{keyId}";

        private string GetDefaultKeyValue() => Environment.GetEnvironmentVariable(AzureWebsiteLocalEncryptionKey) ?? GetMachineConfigKey();

        private static bool IsAzureEnvironment() => Environment.GetEnvironmentVariable(AzureWebsiteInstanceId) != null;

        private static bool IsDefaultKey(Guid keyId) => DefaultKeyId == keyId;

        private static string GetMachineConfigKey()
        {
#if NET46
            return ((System.Web.Configuration.MachineKeySection)System.Configuration.ConfigurationManager.GetSection("system.web/machineKey")).DecryptionKey;
#elif NETSTANDARD1_3
            const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";
            string key = null;

            if (IsAzureEnvironment() && File.Exists(RootWebConfigPath))
            {
                using (var reader = new StringReader(File.ReadAllText(RootWebConfigPath)))
                {
                    var xdoc = XDocument.Load(reader);

                    string siteName = Environment.GetEnvironmentVariable(AzureWebsiteName);
                    string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

                    key = ((IEnumerable)xdoc.XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
                }
            }

            return key;
#endif
        }
    }
}
