using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct ResetStreamFrame
    {
        private ResetStreamFrame(StreamId streamId,
                                 Error error,
                                 int finalSize)
        {
            StreamId = streamId;
            Error = error;
            FinalSize = finalSize;
        }

        public StreamId StreamId { get; }

        public Error Error { get; }

        public int FinalSize { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ResetStreamFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new ResetStreamFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeRemainings);

            if (!type.IsResetStream())
            {
                return false;
            }

            var streamId = StreamId.Parse(afterTypeRemainings, out var afterStreamIdBytes);
            var error = Error.ParseApplication(afterStreamIdBytes, out var afterApplicationErrorBytes);
            var finalSize = VariableLengthEncoding.Decode32(afterApplicationErrorBytes.Span, out var decodedLength);

            result = new ResetStreamFrame(streamId, error, finalSize);
            remainings = afterApplicationErrorBytes.Slice(decodedLength);

            return true;
        }
    }
}
