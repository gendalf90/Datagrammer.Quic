using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct HandshakeRandom
    {
        private readonly ValueBuffer buffer;

        private HandshakeRandom(ValueBuffer buffer)
        {
            this.buffer = buffer;
        }

        public static HandshakeRandom Parse(ReadOnlyMemory<byte> bytes)
        {
            if (bytes.Length != 32)
            {
                throw new EncodingException();
            }

            return new HandshakeRandom(new ValueBuffer(bytes.Span));
        }

        public static HandshakeRandom Parse(MemoryCursor cursor)
        {
            var result = new ValueBuffer(cursor.Move(32).Span);

            return new HandshakeRandom(result);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(32);

            buffer.CopyTo(bytes.Span);
        }

        public static HandshakeRandom Generate()
        {
            Span<byte> bytes = stackalloc byte[32];

            Guid.NewGuid().TryWriteBytes(bytes.Slice(0, 16));
            Guid.NewGuid().TryWriteBytes(bytes.Slice(16, 16));

            return new HandshakeRandom(new ValueBuffer(bytes));
        }

        public override string ToString()
        {
            return buffer.ToString();
        }
    }
}
