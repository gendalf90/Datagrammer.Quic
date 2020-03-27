using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StreamFrame
    {
        private StreamFrame(StreamId streamId,
                            int offset,
                            bool isFinal,
                            ReadOnlyMemory<byte> data)
        {
            StreamId = streamId;
            Offset = offset;
            IsFinal = isFinal;
            Data = data;
        }

        public StreamId StreamId { get; }

        public int Offset { get; }

        public bool IsFinal { get; }

        public ReadOnlyMemory<byte> Data { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StreamFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new StreamFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeBytes))
            {
                return false;
            }

            if (!type.IsStream())
            {
                return false;
            }

            if(!StreamId.TryParse(afterTypeBytes, out var streamId, out var afterStreamIdBytes))
            {
                return false;
            }

            if(!TryParseOffset(afterStreamIdBytes, type, out var offset, out var afterOffsetBytes))
            {
                return false;
            }

            if (!TryParseData(afterOffsetBytes, type, out var data, out var afterDataBytes))
            {
                return false;
            }

            var isFinal = type.HasFinal();

            result = new StreamFrame(streamId, offset, isFinal, data);
            remainings = afterDataBytes;

            return true;
        }

        private static bool TryParseOffset(ReadOnlyMemory<byte> bytes, FrameType type, out int value, out ReadOnlyMemory<byte> remainings)
        {
            value = 0;
            remainings = bytes;

            if(!type.HasOffset())
            {
                return true;
            }

            if(!VariableLengthEncoding.TryDecode32(bytes.Span, out value, out var decodedLength))
            {
                return false;
            }

            remainings = bytes.Slice(decodedLength);

            return true;
        }

        private static bool TryParseData(ReadOnlyMemory<byte> bytes, FrameType type, out ReadOnlyMemory<byte> data, out ReadOnlyMemory<byte> remainings)
        {
            data = bytes;
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!type.HasLength())
            {
                return true;
            }

            if (!VariableLengthEncoding.TryDecode32(bytes.Span, out var length, out var decodedLength))
            {
                return false;
            }

            var afterLengthBytes = bytes.Slice(decodedLength);

            if(afterLengthBytes.Length < length)
            {
                return false;
            }

            data = afterLengthBytes.Slice(0, length);
            remainings = afterLengthBytes.Slice(length);

            return true;
        }
    }
}
