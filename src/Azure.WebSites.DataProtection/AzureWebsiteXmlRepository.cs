using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Repositories;
using static Microsoft.Azure.Web.DataProtection.Constants;

namespace Microsoft.Azure.Web.DataProtection
{
    public class AzureWebsiteXmlRepository : IXmlRepository
    {
        private static Guid DefaultKeyId = Guid.Parse(DefaultEncryptionKeyId);
        private static readonly Regex _keySettingNameRegex = new Regex($"^{AzureWebReferencedKeyPrefix}(?<keyid>[0-9A-Fa-f]{{8}}[-]([0-9A-Fa-f]{{4}}-){{3}}[0-9A-Fa-f]{{12}})$");

        internal static readonly XName KeyElementName = "key";
        internal static readonly XName IdAttributeName = "id";
        internal static readonly XName VersionAttributeName = "version";
        internal static readonly XName CreationDateElementName = "creationDate";
        internal static readonly XName ActivationDateElementName = "activationDate";
        internal static readonly XName ExpirationDateElementName = "expirationDate";
        internal static readonly XName DescriptorElementName = "descriptor";
        internal static readonly XName DeserializerTypeAttributeName = "deserializerType";
        internal static readonly XName RevocationElementName = "revocation";
        internal static readonly XName RevocationDateElementName = "revocationDate";
        internal static readonly XName ReasonElementName = "reason";
        private readonly IAuthenticatedEncryptorConfiguration _encryptorConfiguration;

        public AzureWebsiteXmlRepository(IAuthenticatedEncryptorConfiguration encryptorConfiguration)
        {
            _encryptorConfiguration = encryptorConfiguration;
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
                return Util.ConvertHexToByteArray(keyValue);
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
                    byte[] value = Util.ConvertHexToByteArray(definedKeys[key].ToString());

                    var cryptoKey = new CryptographicKey(keyId, value);

                    keys.Add(cryptoKey);
                }
            }

            

            return keys.Select(k => new XElement(KeyElementName,
                new XAttribute(IdAttributeName, k.Id), 
                new XAttribute(VersionAttributeName, 1),
                new XElement(CreationDateElementName, DateTimeOffset.UtcNow),
                new XElement(ActivationDateElementName, DateTimeOffset.UtcNow),
                new XElement(ExpirationDateElementName, DateTimeOffset.UtcNow.AddYears(10)),
                new XElement(DescriptorElementName,
                new XAttribute(DeserializerTypeAttributeName, CreateSerializedDescryptor() descriptorXmlInfo.DeserializerType.AssemblyQualifiedName),
                descriptorXmlInfo.SerializedDescriptorElement)))
                .ToList()
                .AsReadOnly();
        }

        private XmlSerializedDescriptorInfo CreateSerializedDescryptor()
        {
            var newDescriptor = _encryptorConfiguration.CreateNewDescriptor();
            return newDescriptor.ExportToXml();
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
                        return new CryptographicKey(keyId, Util.ConvertHexToByteArray(value));
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
                return Util.ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        private string GetEnvironmentKey(Guid keyId) => Environment.GetEnvironmentVariable(GetKeySettingName(keyId));

        private string GetKeySettingName(Guid keyId) => $"{AzureWebReferencedKeyPrefix}{keyId}";

        private string GetDefaultKeyValue() => Environment.GetEnvironmentVariable(AzureWebsiteLocalEncryptionKey) ?? GetMachineConfigKey();

        private static bool IsDefaultKey(Guid keyId) => DefaultKeyId == keyId;

        private static string GetMachineConfigKey()
        {
#if NET46
            string key = ((System.Web.Configuration.MachineKeySection)System.Configuration.ConfigurationManager.GetSection("system.web/machineKey")).DecryptionKey;

            // This will not happen when hosted in Azure App Service.
            if (!string.IsNullOrEmpty(key) && (key.IndexOf("AutoGenerate") != -1 || key.IndexOf("IsolateApps") != -1))
            {
                return null;
            }

            return key;

#elif NETSTANDARD1_3
            const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";
            string key = null;

            if (Util.IsAzureEnvironment() && File.Exists(RootWebConfigPath))
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
