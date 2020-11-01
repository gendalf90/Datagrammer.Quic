using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CertificateEntryList
    {
        private readonly ReadOnlyMemory<byte> bytes;

        public CertificateEntryList(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public CertificateEntryEnumerator GetEnumerator()
        {
            return new CertificateEntryEnumerator(bytes);
        }

        public struct CertificateEntryEnumerator
        {
            private ReadOnlyMemory<byte> remainings;
            private CertificateEntry? current;

            public CertificateEntryEnumerator(ReadOnlyMemory<byte> bytes)
            {
                remainings = bytes;
                current = null;
            }

            public CertificateEntry Current => current ?? throw new ArgumentOutOfRangeException(nameof(Current));

            public bool MoveNext()
            {
                current = null;

                if(remainings.IsEmpty)
                {
                    return false;
                }

                current = CertificateEntry.Parse(remainings, out remainings);

                return true;
            }
        }
    }
}
