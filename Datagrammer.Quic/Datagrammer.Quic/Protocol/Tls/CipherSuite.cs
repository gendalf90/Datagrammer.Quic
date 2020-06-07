using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly ReadOnlyMemory<Cipher> ciphers;
        private readonly ReadOnlyMemory<byte> bytes;

        private CipherSuite(ReadOnlyMemory<byte> bytes, ReadOnlyMemory<Cipher> ciphers)
        {
            this.bytes = bytes;
            this.ciphers = ciphers;
        }

        public bool HasCipher(Cipher cipherToSearch)
        {
            foreach(var cipher in ciphers.Span)
            {
                if(cipher == cipherToSearch)
                {
                    return true;
                }
            }

            var remainings = bytes;

            while (!remainings.IsEmpty)
            {
                if (Cipher.Parse(remainings, out remainings) == cipherToSearch)
                {
                    return true;
                }
            }

            return false;
        }

        public static CipherSuite Supported { get; } = new CipherSuite(ReadOnlyMemory<byte>.Empty, new[] { Cipher.TLS_AES_128_GCM_SHA256 });
        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out remainings);

            return new CipherSuite(data, ReadOnlyMemory<Cipher>.Empty);
        }

        public void WriteBytes(ref WritingCursor cursor)
        {
            var vectorContext = ByteVector.StartVectorWriting(cursor.Destination, 2..ushort.MaxValue);
            var vectorCursor = vectorContext.Cursor;

            foreach (var cipher in ciphers.Span)
            {
                cipher.WriteBytes(ref vectorCursor);
            }

            vectorCursor = vectorCursor.Write(bytes.Span);

            vectorContext.Cursor = vectorCursor;
            cursor = cursor.Move(vectorContext.Complete());
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
