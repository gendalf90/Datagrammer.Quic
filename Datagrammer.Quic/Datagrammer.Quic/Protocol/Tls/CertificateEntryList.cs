using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CertificateEntryList
    {
        private readonly MemoryCursor cursor;

        public CertificateEntryList(MemoryCursor cursor)
        {
            this.cursor = cursor;
        }

        public CertificateEntryEnumerator GetEnumerator()
        {
            return new CertificateEntryEnumerator(cursor);
        }

        public struct CertificateEntryEnumerator
        {
            private MemoryCursor cursor;
            private CertificateEntry? current;

            public CertificateEntryEnumerator(MemoryCursor cursor)
            {
                this.cursor = cursor;

                current = null;
            }

            public CertificateEntry Current => current ?? throw new ArgumentOutOfRangeException(nameof(Current));

            public bool MoveNext()
            {
                current = null;

                if(!cursor.HasNext())
                {
                    return false;
                }

                current = CertificateEntry.Parse(cursor);

                return true;
            }
        }
    }
}
