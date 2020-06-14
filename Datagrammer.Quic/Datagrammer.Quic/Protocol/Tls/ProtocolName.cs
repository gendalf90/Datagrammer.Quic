using Datagrammer.Quic.Protocol.Error;
using System;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ProtocolName
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private ProtocolName(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static ProtocolName Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 1..byte.MaxValue, out remainings);

            return new ProtocolName(data);
        }

        public static ProtocolName H3_20 { get; } = new ProtocolName(Encoding.UTF8.GetBytes("h3-20"));

        public void WriteBytes(ref Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(ref destination, 1..byte.MaxValue);

            if(!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(bytes.Span);
        }
    }
}
