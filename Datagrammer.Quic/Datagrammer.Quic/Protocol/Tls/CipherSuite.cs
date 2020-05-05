using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly Cipher? tlsaes128gcmsha256;

        private CipherSuite(Cipher? tlsaes128gcmsha256)
        {
            this.tlsaes128gcmsha256 = tlsaes128gcmsha256;
        }

        public bool TryGetFirstSupported(out Cipher cipher)
        {
            cipher = new Cipher();

            if(tlsaes128gcmsha256.HasValue)
            {
                cipher = tlsaes128gcmsha256.Value;
                return true;
            }

            return false;
        }

        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out bytes);

            remainings = bytes;

            return ParseSupported(data);
        }

        private static CipherSuite ParseSupported(ReadOnlyMemory<byte> bytes)
        {
            var remainings = bytes;
            var tlsaes128gcmsha256 = new Cipher?();

            while (!remainings.IsEmpty)
            {
                var current = Cipher.Parse(remainings, out remainings);

                if (current == Cipher.TLS_AES_128_GCM_SHA256)
                {
                    tlsaes128gcmsha256 = current;
                }
            }

            return new CipherSuite(tlsaes128gcmsha256);
        }

        public static CipherSuite TLS_AES_128_GCM_SHA256_Only { get; } = new CipherSuite(Cipher.TLS_AES_128_GCM_SHA256);

        public int WriteBytes(Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(destination);

            if(tlsaes128gcmsha256.HasValue)
            {
                context.Move(tlsaes128gcmsha256.Value.WriteBytes(context.Current));
            }

            return ByteVector.FinishVectorWriting(context, 2..ushort.MaxValue);
        }
    }
}
