using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StopSendingFrame
    {
        private StopSendingFrame(StreamId streamId,
                                 ApplicationError applicationError)
        {
            StreamId = streamId;
            ApplicationError = applicationError;
        }

        public StreamId StreamId { get; }

        public ApplicationError ApplicationError { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StopSendingFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new StopSendingFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeRemainings))
            {
                return false;
            }

            if (!type.IsStopSending())
            {
                return false;
            }

            if (!StreamId.TryParse(afterTypeRemainings, out var streamId, out var afterStreamIdBytes))
            {
                return false;
            }

            if (!ApplicationError.TryParse(afterStreamIdBytes, out var applicationError, out var afterApplicationErrorBytes))
            {
                return false;
            }

            result = new StopSendingFrame(streamId, applicationError);
            remainings = afterApplicationErrorBytes;

            return true;
        }
    }
}
