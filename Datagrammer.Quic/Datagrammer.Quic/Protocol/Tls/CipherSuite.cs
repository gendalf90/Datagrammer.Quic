using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private CipherSuite(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static void Write(MemoryCursor cursor, ReadOnlyMemory<Cipher> ciphers)
        {
            using var context = ByteVector.StartVectorWriting(cursor, 2..ushort.MaxValue);

            foreach (var cipher in ciphers.Span)
            {
                cipher.WriteBytes(cursor);
            }
        }

        public Enumerator GetEnumerator()
        {
            return new Enumerator(bytes);
        }

        public static CipherSuite Parse(MemoryCursor cursor)
        {
            var buffer = ByteVector.SliceVectorBytes(cursor, 2..ushort.MaxValue);

            return new CipherSuite(buffer.Read(cursor));
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }

        public ref struct Enumerator
        {
            private Cipher? current;
            private ReadOnlyMemory<byte> remainings;

            public Enumerator(ReadOnlyMemory<byte> bytes)
            {
                remainings = bytes;
                current = null;
            }

            public Cipher Current => current ?? throw new ArgumentOutOfRangeException(nameof(Current));

            public bool MoveNext()
            {
                current = null;

                if(remainings.IsEmpty)
                {
                    return false;
                }

                current = Cipher.Parse(ref remainings);

                return true;
            }
        }
    }
}
