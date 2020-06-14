using Datagrammer.Quic.Protocol.Error;
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

        public void WriteBytes(ref Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(ref destination, 1..ushort.MaxValue);

            if(!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }
    }
}
