// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Linq;

namespace Microsoft.Azure.Web.DataProtection
{
    public class CryptographicKey
    {
        private readonly byte[] _value;

        public CryptographicKey(string id, byte[] value)
        {
            Id = id;
            _value = value;
        }

        public string Id { get; }

        public byte[] GetValue() => _value.ToArray();

        private static byte[] ConvertHexToByteArray(string keyValue)
            => Enumerable.Range(0, keyValue.Length / 2)
            .Select(b => Convert.ToByte(keyValue.Substring(b * 2, 2), 16))
            .ToArray();

        public static CryptographicKey FromHexString(string id, string value)
        {
            byte[] bytes = ConvertHexToByteArray(value);

            return new CryptographicKey(id, bytes);
        }
    }
}
