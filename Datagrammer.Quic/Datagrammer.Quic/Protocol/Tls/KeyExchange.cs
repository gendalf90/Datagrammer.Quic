using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct KeyExchange
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private KeyExchange(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static KeyExchange Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 1..ushort.MaxValue, out remainings);

            return new KeyExchange(data);
        }

        public int WriteBytes(Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(destination);

            context.Write(bytes.Span);

            return ByteVector.FinishVectorWriting(context, 1..ushort.MaxValue);
        }
    }
}
