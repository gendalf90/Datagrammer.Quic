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

            if (!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeRemainings))
            {
                return false;
            }

            if(!type.IsResetStream())
            {
                return false;
            }

            if (!StreamId.TryParse(afterTypeRemainings, out var streamId, out var afterStreamIdBytes))
            {
                return false;
            }

            if(!ApplicationError.TryParse(afterStreamIdBytes, out var applicationError, out var afterApplicationErrorBytes))
            {
                return false;
            }

            if (!VariableLengthEncoding.TryDecode32(afterApplicationErrorBytes.Span, out var finalSize, out var decodedLength))
            {
                return false;
            }

            result = new ResetStreamFrame(streamId, applicationError, finalSize);
            remainings = afterApplicationErrorBytes.Slice(decodedLength);

            return true;
        }
    }
}
