using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct ResetStreamFrame
    {
        private ResetStreamFrame(StreamId streamId,
                                 ApplicationError applicationError,
                                 int finalSize)
        {
            StreamId = streamId;
            ApplicationError = applicationError;
            FinalSize = finalSize;
        }

        public StreamId StreamId { get; }

        public ApplicationError ApplicationError { get; }

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
            var applicationError = ApplicationError.Parse(afterStreamIdBytes, out var afterApplicationErrorBytes);
            var finalSize = VariableLengthEncoding.Decode32(afterApplicationErrorBytes.Span, out var decodedLength);

            result = new ResetStreamFrame(streamId, applicationError, finalSize);
            remainings = afterApplicationErrorBytes.Slice(decodedLength);

            return true;
        }
    }
}
