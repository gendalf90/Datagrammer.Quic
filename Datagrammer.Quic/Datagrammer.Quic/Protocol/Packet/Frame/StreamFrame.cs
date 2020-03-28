using Datagrammer.Quic.Protocol.Error;
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

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsStream())
            {
                return false;
            }

            var streamId = StreamId.Parse(afterTypeBytes, out var afterStreamIdBytes);
            var offset = ParseOffset(afterStreamIdBytes, type, out var afterOffsetBytes);
            var data = ParseData(afterOffsetBytes, type, out var afterDataBytes);
            var isFinal = type.HasFinal();

            result = new StreamFrame(streamId, offset, isFinal, data);
            remainings = afterDataBytes;

            return true;
        }

        private static int ParseOffset(ReadOnlyMemory<byte> bytes, FrameType type,  out ReadOnlyMemory<byte> remainings)
        {
            remainings = bytes;

            if(!type.HasOffset())
            {
                return 0;
            }

            var offset = VariableLengthEncoding.Decode32(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return offset;
        }

        private static ReadOnlyMemory<byte> ParseData(ReadOnlyMemory<byte> bytes, FrameType type, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!type.HasLength())
            {
                return bytes;
            }

            var length = VariableLengthEncoding.Decode32(bytes.Span, out var decodedLength);
            var afterLengthBytes = bytes.Slice(decodedLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            remainings = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }
    }
}
