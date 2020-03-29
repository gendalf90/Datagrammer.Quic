using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StopSendingFrame
    {
        private StopSendingFrame(StreamId streamId,
                                 Error applicationError)
        {
            StreamId = streamId;
            ApplicationError = applicationError;
        }

        public StreamId StreamId { get; }

        public Error ApplicationError { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StopSendingFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new StopSendingFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeRemainings);

            if (!type.IsStopSending())
            {
                return false;
            }

            var streamId = StreamId.Parse(afterTypeRemainings, out var afterStreamIdBytes);
            var applicationError = Error.ParseApplication(afterStreamIdBytes, out var afterApplicationErrorBytes);

            result = new StopSendingFrame(streamId, applicationError);
            remainings = afterApplicationErrorBytes;

            return true;
        }
    }
}
