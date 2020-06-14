using Datagrammer.Quic.Protocol.Error;
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

        public void WriteBytes(ref Span<byte> destination)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref destination, 2..ushort.MaxValue);

            foreach (var cipher in ciphers.Span)
            {
                cipher.WriteBytes(ref destination);
            }

            if(!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            vectorContext.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
