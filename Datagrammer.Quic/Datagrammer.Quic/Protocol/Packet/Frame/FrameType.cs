﻿using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct FrameType : IEquatable<FrameType>
    {
        private readonly ulong type;

        private FrameType(ulong type)
        {
            this.type = type;
        }

        public bool IsPing() => type == 1;

        public bool IsAck => type == 2 || type == 3;

        public bool HasAckEcnFeedback => type == 3;

        public bool IsResetStream() => type == 4;

        public bool IsStopSending() => type == 5;

        public bool IsCrypto() => type == 6;

        public bool IsNewToken() => type == 7;

        public bool IsStream() => type >= 8 && type <= 15;

        public bool HasOffset() => Convert.ToBoolean((type >> 2) & 1);

        public bool HasLength() => Convert.ToBoolean((type >> 1) & 1);

        public bool HasFinal() => Convert.ToBoolean(type & 1);

        public bool IsMaxData() => type == 16;

        public bool IsMaxStreamData() => type == 17;

        public bool IsMaxStreams() => type == 18 || type == 19;

        public bool ForBidirectional() => type == 18 || type == 22;

        public bool ForUnidirectional() => type == 19 || type == 23;

        public bool IsDataBlocked() => type == 20;

        public bool IsStreamDataBlocked() => type == 21;

        public bool IsStreamsBlocked() => type == 22 || type == 23;

        public bool IsNewConnectionId() => type == 24;

        public bool IsRetireConnectionId() => type == 25;

        public bool IsPath() => type == 26 || type == 27;

        public bool IsChallenge() => type == 26;

        public bool IsResponse() => type == 27;

        public bool IsConnectionClose() => type == 28 || type == 29;

        public bool HasTransportError() => type == 28;

        public bool HasApplicationError() => type == 29;

        public bool IsHandshakeDone() => type == 30;

        public static FrameType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var code = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new FrameType(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            VariableLengthEncoding.Encode(bytes, type, out var encodedLength);

            bytes = bytes.Slice(encodedLength);
        }

        public void Write(MemoryCursor cursor)
        {
            cursor.EncodeVariable(type);
        }

        public static bool TrySlice(MemoryCursor cursor, FrameType expected)
        {
            var bytes = cursor.PeekEnd();
            var type = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            if (type != expected.type)
            {
                return false;
            }

            cursor.Move(decodedLength);

            return true;
        }

        public static FrameType Peek(MemoryCursor cursor)
        {
            var bytes = cursor.PeekEnd();
            var value = VariableLengthEncoding.Decode(bytes.Span, out _);

            return new FrameType(value);
        }

        public void Slice(MemoryCursor cursor)
        {
            var length = VariableLengthEncoding.GetLength(type);

            cursor.Move(length);
        }

        public static FrameType Crypto { get; } = new FrameType(6);

        public static FrameType Padding { get; } = new FrameType(0);

        public static FrameType Ping { get; } = new FrameType(1);

        public static FrameType CreateAck(bool withEcn = false) => new FrameType(withEcn ? 3ul : 2ul);

        public bool Equals(FrameType other)
        {
            return type == other.type;
        }

        public override bool Equals(object obj)
        {
            return obj is FrameType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return type.GetHashCode();
        }

        public static bool operator ==(FrameType first, FrameType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(FrameType first, FrameType second)
        {
            return !first.Equals(second);
        }
    }
}
