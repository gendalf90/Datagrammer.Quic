using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct SessionId : IEquatable<SessionId>
    {
        private readonly ValueBuffer buffer;

        private SessionId(ValueBuffer buffer)
        {
            this.buffer = buffer;
        }

        public override bool Equals(object obj)
        {
            return obj is SessionId version && Equals(version);
        }

        public override int GetHashCode()
        {
            return buffer.GetHashCode();
        }

        public bool Equals(SessionId other)
        {
            return buffer == other.buffer;
        }

        public static bool operator ==(SessionId first, SessionId second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(SessionId first, SessionId second)
        {
            return !first.Equals(second);
        }

        public static SessionId Empty { get; } = new SessionId();

        public static SessionId Parse(MemoryCursor cursor)
        {
            var buffer = ByteVector.SliceVectorBytes(cursor, 0..32);
            var result = new ValueBuffer(buffer.Read(cursor).Span);

            return new SessionId(result);
        }

        public static SessionId Parse(ReadOnlyMemory<byte> bytes)
        {
            var idBytes = ByteVector.SliceVectorBytes(bytes, 0..32, out var remainings);

            if(!remainings.IsEmpty)
            {
                throw new EncodingException();
            }

            return new SessionId(new ValueBuffer(idBytes.Span));
        }

        public static SessionId Generate()
        {
            Span<byte> bytes = stackalloc byte[32];

            Guid.NewGuid().TryWriteBytes(bytes.Slice(0, 16));
            Guid.NewGuid().TryWriteBytes(bytes.Slice(16, 16));

            return new SessionId(new ValueBuffer(bytes));
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            using var context = ByteVector.StartVectorWriting(cursor, 0..32);

            buffer.CopyTo(cursor);
        }

        public override string ToString()
        {
            return buffer.ToString();
        }
    }
}
