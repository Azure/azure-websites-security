using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Azure.Web.DataProtection
{
    public class CryptographicKey
    {
        public CryptographicKey(Guid id, byte[] value)
        {
            Id = id;
            Value = value;
        }

        public Guid Id { get; }

        public byte[] Value { get; }
    }
}
