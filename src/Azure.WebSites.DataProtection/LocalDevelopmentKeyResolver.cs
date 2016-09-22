// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Microsoft.Azure.Web.DataProtection.Constants;

namespace Microsoft.Azure.Web.DataProtection
{
    public class LocalDevelopmentKeyResolver : IEncryptionKeyResolver
    {
        private readonly Dictionary<Guid, byte[]> _keys = new Dictionary<Guid, byte[]>();
        
        /// <summary>
        /// Initializes a new instance of a <see cref="LocalDevelopmentKeyResolver"/> with a new, random key.
        /// </summary>
        public LocalDevelopmentKeyResolver()
            : this(CryptoUtil.CreateKey())
        {
            
        }

        /// <summary>
        /// Initializes a new instance of a <see cref="LocalDevelopmentKeyResolver"/> with the provided key.
        /// </summary>
        /// <param name="testKey">The hexadecimal string representation of the key to be used by the key resolver</param>
        public LocalDevelopmentKeyResolver(string testKey)
            : this(CryptoUtil.ConvertHexToByteArray(testKey))
        {
        }

        /// <summary>
        /// Initializes a new instance of a <see cref="LocalDevelopmentKeyResolver"/> with the provided key.
        /// </summary>
        /// <param name="testKey">The key to be used by the key resolver.</param>
        public LocalDevelopmentKeyResolver(byte[] testKey)
        {
            _keys.Add(Guid.Parse(DefaultEncryptionKeyId), testKey);
        }

        public byte[] ResolveKey(Guid keyId)
        {
            byte[] result;
            _keys.TryGetValue(keyId, out result);

            return result;
        }

        public IReadOnlyCollection<CryptographicKey> GetAllKeys()
        {
            return _keys.Select(kv => new CryptographicKey(kv.Key, kv.Value)).ToList().AsReadOnly();
        }
    }
}
