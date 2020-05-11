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

        public bool HasCipher(Cipher cipher)
        {
            var remainings = bytes;

            while (!remainings.IsEmpty)
            {
                if (Cipher.Parse(remainings, out remainings) == cipher)
                {
                    return true;
                }
            }

            return false;
        }

        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out remainings);

            return new CipherSuite(data);
        }

        public static int WriteWithCipher(Span<byte> destination, Cipher cipher)
        {
            var context = ByteVector.StartVectorWriting(destination);

            context.Move(cipher.WriteBytes(context.Remainings));

            return ByteVector.FinishVectorWriting(context, 2..ushort.MaxValue);
        }
    }
}
