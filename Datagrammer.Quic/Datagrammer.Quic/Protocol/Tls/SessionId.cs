using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct SessionId : IEquatable<SessionId>
    {
        private const int MaxLength = 32;

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
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var length = bytes.Span[0];

            if (length > MaxLength)
            {
                throw new EncodingException();
            }

            var afterLengthBytes = bytes.Slice(1);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            var resultBytes = afterLengthBytes.Slice(0, length);
            var resultGuid = length == 16 ? new Guid(resultBytes.Span) : Guid.Empty;

            remainings = afterLengthBytes.Slice(length);

            return new SessionId(resultBytes, resultGuid);
        }

        public static SessionId Generate()
        {
            return new SessionId(ReadOnlyMemory<byte>.Empty, Guid.NewGuid());
        }

        public void WriteBytes(Span<byte> destination, out Span<byte> remainings)
        {
            if(destination.IsEmpty)
            {
                throw new EncodingException();
            }

            var lengthOfValue = IsGuid ? 16 : rawBytes.Length;
            var destinationOfValue = destination.Slice(1);
            var isWritingSuccess = IsGuid 
                ? guid.TryWriteBytes(destinationOfValue) 
                : rawBytes.Span.TryCopyTo(destinationOfValue);

            if(!isWritingSuccess)
            {
                throw new EncodingException();
            }

            destination[0] = (byte)lengthOfValue;
            remainings = destinationOfValue.Slice(lengthOfValue);
        }

        public override string ToString()
        {
            var bytes = IsGuid ? guid.ToByteArray() : rawBytes.ToArray();

            return BitConverter.ToString(bytes);
        }
    }
}
