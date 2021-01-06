using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Packet
{
    public class InitialServerHelloTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHex();
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var version = PacketVersion.CreateByDraft(29);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var serverHelloBytes = Utils.ParseHexString(GetServerHelloHex());

            //Act
            var cursor = new MemoryCursor(buffer);

            using (InitialPacket.StartWriting(cursor, version, destConnectionId, sourceConnectionId, packetNumber, token))
            {
                AckFrame
                    .StartWriting(cursor, AckDelay.CreateDelay(TimeSpan.FromTicks(47120)), PacketNumber.Initial, 0)
                    .Finish();

                using (CryptoFrame.StartWriting(cursor, 0))
                {
                    serverHelloBytes.CopyTo(cursor);
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Read_ResultsAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetMessageHex());
            var version = PacketVersion.CreateByDraft(29);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var serverHelloBytes = GetServerHelloHex();
            var cryptoFrame = new CryptoFrame();
            var ackFrame = new AckFrame();
            var ackRanges = new List<AckRange>();

            //Act
            var cursor = new MemoryCursor(messageBytes);
            var result = InitialPacket.TryParse(cursor, out var packet);

            using (packet.Payload.SetCursor(cursor))
            {
                result &= AckFrame.TryParse(cursor, out ackFrame);

                foreach(var ackRange in ackFrame.Ranges)
                {
                    ackRanges.Add(ackRange);
                }

                result &= CryptoFrame.TryParse(cursor, out cryptoFrame);

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(version, packet.Version);
            Assert.Equal(sourceConnectionId, packet.SourceConnectionId);
            Assert.Equal(destConnectionId, packet.DestinationConnectionId);
            Assert.Equal(packetNumber, packet.Number);
            Assert.Equal(token, packet.Token);
            Assert.Equal(0, cryptoFrame.Offset);
            Assert.Equal(serverHelloBytes, Utils.ToHexString(cryptoFrame.Data.Read(cursor).ToArray()), true);
            Assert.Single(ackRanges);
            Assert.True(ackRanges.First().IsAck);
            Assert.False(ackRanges.First().IsGap);
            Assert.Equal(0, ackRanges.First().Length);
            Assert.Equal(TimeSpan.FromTicks(47120), ackFrame.Delay.GetDelay());
            Assert.Equal(PacketNumber.Initial, ackFrame.LargestAcknowledged);
            Assert.Null(ackFrame.EcnFeedback);
        }

        private string GetMessageHex()
        {
            return "c0ff00001d08456a257f62d8338e14a3744afcffd5ff8a2a1b87e7fc43c10f44c5ef0f004086000200424d00000600407b02000077030314f927bd332de73c5346843fc452b03633030661b5134b5015545c93754ace7e00130200004f0033004500170041048753d4b6f306241077a53f3572f900aba51d016f91f424b6a7077ce1f1104c069f60e46c16a19fc5566e96f63f9fb5e4017a1354e67676993aa42d818b5e656d002b00020304";
        }

        private (string DestConnectionIdHex, string SourceConnectionIdHex) GetConnectionIdsHex()
        {
            return ("08456a257f62d8338e", "14a3744afcffd5ff8a2a1b87e7fc43c10f44c5ef0f");
        }

        private string GetPacketNumberHex()
        {
            return "00";
        }

        private string GetServerHelloHex()
        {
            return "02000077030314f927bd332de73c5346843fc452b03633030661b5134b5015545c93754ace7e00130200004f0033004500170041048753d4b6f306241077a53f3572f900aba51d016f91f424b6a7077ce1f1104c069f60e46c16a19fc5566e96f63f9fb5e4017a1354e67676993aa42d818b5e656d002b00020304";
        }
    }
}
