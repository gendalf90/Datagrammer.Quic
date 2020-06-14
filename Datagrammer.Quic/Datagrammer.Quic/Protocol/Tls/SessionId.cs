using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct SessionId : IEquatable<SessionId>
    {
        private readonly ReadOnlyMemory<byte> rawBytes;
        private readonly Guid guid;

        private SessionId(ReadOnlyMemory<byte> rawBytes, Guid guid)
        {
            this.rawBytes = rawBytes;
            this.guid = guid;
        }

        public override bool Equals(object obj)
        {
            return obj is SessionId version && Equals(version);
        }

        public override int GetHashCode()
        {
            if (IsGuid)
            {
                return guid.GetHashCode();
            }

            return HashCodeCalculator.Calculate(rawBytes.Span);
        }

        public bool Equals(SessionId other)
        {
            if (other.IsGuid != IsGuid)
            {
                return false;
            }

            if (other.IsGuid && IsGuid)
            {
                return other.guid == guid;
            }

            return rawBytes.Span.SequenceEqual(other.rawBytes.Span);
        }

        private bool IsGuid => guid != Guid.Empty;

        public static bool operator ==(SessionId first, SessionId second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(SessionId first, SessionId second)
        {
            return !first.Equals(second);
        }

        public static SessionId Empty { get; } = new SessionId();

        public static SessionId Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var idBytes = ByteVector.SliceVectorBytes(bytes, 0..32, out remainings);
            var resultGuid = idBytes.Length == 16 ? new Guid(idBytes.Span) : Guid.Empty;

            return new SessionId(idBytes, resultGuid);
        }

        public static SessionId Generate()
        {
            return new SessionId(ReadOnlyMemory<byte>.Empty, Guid.NewGuid());
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            var context = ByteVector.StartVectorWriting(ref bytes, 0..32);

            var lengthOfValue = IsGuid ? 16 : rawBytes.Length;
            var isWritingSuccess = IsGuid
                ? guid.TryWriteBytes(bytes)
                : rawBytes.Span.TryCopyTo(bytes);

            if (!isWritingSuccess)
            {
                throw new EncodingException();
            }

            bytes = bytes.Slice(lengthOfValue);

            context.Complete(ref bytes);
        }

        public override string ToString()
        {
            var bytes = IsGuid ? guid.ToByteArray() : rawBytes.ToArray();

            return BitConverter.ToString(bytes);
        }
    }
}
