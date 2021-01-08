using System;

namespace Datagrammer.Quic.Protocol.Packet.TransportParameters
{
    public readonly struct TransportParameterType : IEquatable<TransportParameterType>
    {
        private readonly ulong id;

        private TransportParameterType(ulong id)
        {
            this.id = id;
        }

        public static TransportParameterType Parse(MemoryCursor cursor)
        {
            return new TransportParameterType(cursor.DecodeVariable());
        }

        public void Write(MemoryCursor cursor)
        {
            cursor.EncodeVariable(id);
        }

        public static bool TrySlice(MemoryCursor cursor, TransportParameterType expected)
        {
            var bytes = cursor.PeekEnd();
            var id = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            if (id != expected.id)
            {
                return false;
            }

            cursor.Move(decodedLength);

            return true;
        }

        public static TransportParameterType InitialSourceConnectionId { get; } = new TransportParameterType(0x0f);

        public bool Equals(TransportParameterType other)
        {
            return id == other.id;
        }

        public override bool Equals(object obj)
        {
            return obj is TransportParameterType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return id.GetHashCode();
        }

        public static bool operator ==(TransportParameterType first, TransportParameterType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(TransportParameterType first, TransportParameterType second)
        {
            return !first.Equals(second);
        }
    }
}
