package gtrboy.learning.IKEv2;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import gtrboy.learning.IKEv2.parsers.IKEv2Parser;
import gtrboy.learning.utils.DataUtils;
import org.apache.commons.net.DatagramSocketClient;
import org.apache.commons.net.tftp.TFTPPacket;
import org.apache.commons.net.tftp.TFTPPacketException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IKEv2 extends DatagramSocketClient {

    /**
     * The default number of milliseconds to wait to receive a datagram
     * before timing out.  The default is 500 milliseconds (0.5 seconds).
     */
    public static final int DEFAULT_TIMEOUT = 500;

    public static final int DEFAULT_PORT = 500;

    private static final int PACKET_SIZE = 1024;

    private byte[] receiveBuffer;

    /** A datagram used to minimize memory allocation in bufferedReceive() */
    private DatagramPacket receiveDatagram;

    /** A datagram used to minimize memory allocation in bufferedSend() */
    private DatagramPacket sendDatagram;

    /**
     * A buffer used to accelerate sends in bufferedSend().
     * It is left package visible so that TFTPClient may be slightly more
     * efficient during file sends.  It saves the creation of an
     * additional buffer and prevents a buffer copy in _newDataPcket().
     */
    byte[] sendBuffer;

    protected int g_wantedMsgId = 0;

    protected static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public IKEv2()
    {
        setDefaultTimeout(DEFAULT_TIMEOUT);
        receiveBuffer = null;
        receiveDatagram = null;
    }

    /**
     * Initializes the internal buffers. Buffers are used by
     * {@link #bufferedSend  bufferedSend() } and
     * {@link #bufferedReceive  bufferedReceive() }.  This
     * method must be called before calling either one of those two
     * methods.  When you finish using buffered operations, you must
     * call {@link #endBufferedOps  endBufferedOps() }.
     */
    public final void beginBufferedOps()
    {
        receiveBuffer = new byte[PACKET_SIZE];
        receiveDatagram =
                new DatagramPacket(receiveBuffer, receiveBuffer.length);
        sendBuffer = new byte[PACKET_SIZE];
        sendDatagram =
                new DatagramPacket(sendBuffer, sendBuffer.length);
    }

    boolean validatePkt(DatagramPacket packet){
        boolean ret;
        byte[] bPkt = packet.getData();
        byte exchType = bPkt[18];
        byte flags = bPkt[19];
        int msgId = DataUtils.bytesToIntB(bPkt, 20);
        //LOGGER.debug("Msg Id: " + msgId);
        // discard cmd del information packet or init request packet
        if(flags==0x00 || flags==0x08){
            byte[] tmp = new byte[1];
            tmp[0] = flags;
            byte[] tmp1 = new byte[1];
            tmp1[0] = exchType;
            LOGGER.debug("Find invalid flags or exchange type. Flags: " + DataUtils.bytesToHexStr(tmp) +
                    " Exchange Type: " + DataUtils.bytesToHexStr(tmp1));
            ret = false;
        }else if(msgId!= g_wantedMsgId) {
            LOGGER.debug("Find unwanted Msg ID: " + msgId);
            ret = false;
        }else {
            ret = true;
        }
        return ret;
    }

    public final IKEv2Parser bufferedReceive(IKEv2KeysGener keysGener) throws IOException {
        receiveDatagram.setData(receiveBuffer);
        receiveDatagram.setLength(receiveBuffer.length);
        while(true) {
            _socket_.receive(receiveDatagram);
            if(validatePkt(receiveDatagram)){
                break;
            }
        }
        return IKEv2Parser.newIKEv2Parser(receiveDatagram, keysGener);
    }

    public final void bufferedSend(final byte[] pkt_bytes, String peerAddr, int port) throws IOException
    {
        InetSocketAddress peerSocketAddr = new InetSocketAddress(peerAddr, port);
        DatagramPacket packet = new DatagramPacket(pkt_bytes, pkt_bytes.length, peerSocketAddr);
        _socket_.send(packet);
    }

    public final void endBufferedOps()
    {
        receiveBuffer = null;
        receiveDatagram = null;
        sendBuffer = null;
        sendDatagram = null;
    }

}
