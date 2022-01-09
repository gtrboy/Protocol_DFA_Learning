package gtrboy.learning.utils;

import java.io.InputStream;
import java.io.PrintStream;

import org.apache.commons.net.telnet.TelnetClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

//import com.telnet.constant.TelnetConstant;

public class TelnetMain {

    private TelnetClient telnet = new TelnetClient("VT100");

    private InputStream in;

    private PrintStream out;

    private static final String CISCO_AIX_PROMPT = "#";
    private static final String CISCO_COMMAND_ARROW = ">";

    /**
     * IP 地址
     */
    private final String ip;

    /**
     * telnet 端口
     */
    private final String port;

    /**
     * 用户名
     */
    private final String user;

    /**
     * 密码
     */
    private final String password;

    private final String _sul;

    private static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);
    private static final String CISCO_RESET_CMD = "clear crypto ikev2 sa fast";

    private static final String FG_RESET_CMD = "diagnose vpn ike gateway clear";

    private static final String HS_RESET_CMD1 = "conf";
    private static final String HS_RESET_CMD2 = "tunnel ipsec ipsec-test ikev2";
    private static final String HS_RESET_CMD3 = "no ikev2-peer";
    private static final String HS_RESET_CMD4 = "ikev2-peer v2";
    private static final String HS_RESET_CMD5 = "end";
    //private static final String FG_FLUSH_CMD = "diagnose vpn tunnel flush";



    public TelnetMain(String ip, String user, String password, String sul) {
        this.ip = ip;
        this.port = String.valueOf(23);
        this.user = user;
        this.password = password;
        this._sul = sul;
    }


    public void connect() {

        switch (_sul){
            case "cisco7200":
                try {
                    telnet.connect(ip, Integer.parseInt(port));
                    in = telnet.getInputStream();
                    out = new PrintStream(telnet.getOutputStream());
                    telnet.setKeepAlive(true);
                    write(password);
                    String msg=readUntil(CISCO_COMMAND_ARROW);
                    write("en");
                    msg=readUntil("Password:");
                    write(password);
                    msg=readUntil(CISCO_AIX_PROMPT);

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case "fortigate":
                try {
                    telnet.connect(ip, Integer.parseInt(port));
                    in = telnet.getInputStream();
                    out = new PrintStream(telnet.getOutputStream());
                    telnet.setKeepAlive(true);
                    write(user);
                    String msg=readUntil("Password: ");
                    write(password);
                    msg=readUntil("# ");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case "hillstone":
                try {
                    telnet.connect(ip, Integer.parseInt(port));
                    in = telnet.getInputStream();
                    out = new PrintStream(telnet.getOutputStream());
                    telnet.setKeepAlive(true);
                    String msg;
                    msg = readUntil("login: ");
                    write(user);
                    msg=readUntil("password: ");
                    write(password);
                    msg=readUntil("# ");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                LOGGER.error("Invalid SUL Name! ");
                System.exit(-1);
        }
    }


    public String readUntil(String pattern) {
        try {
            char lastChar = pattern.charAt(pattern.length() - 1);
            StringBuffer sb = new StringBuffer();
            char ch = (char) in.read();
            while (true) {
                sb.append(ch);
                if (ch == lastChar) {
                    if (sb.toString().endsWith(pattern)) {
                        return sb.toString();
                    }
                }
                ch = (char) in.read();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void write(String value) {
        try {
            out.println(value);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void resetCisco(){
        sendCommand(CISCO_RESET_CMD);
    }

    public void resetFG(){
        sendCommand(FG_RESET_CMD);
        //sendCommand(FG_FLUSH_CMD);
    }

    public void resetHS(){

        sendCommand(HS_RESET_CMD1);
        sendCommand(HS_RESET_CMD2);
        sendCommand(HS_RESET_CMD3);
        sendCommand(HS_RESET_CMD4);
        sendCommand(HS_RESET_CMD5);

        //sendCommand(FG_FLUSH_CMD);
    }

    private String sendCommand(String command) {
        try {
            write(command);
            return readUntil(CISCO_AIX_PROMPT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public void disconnect() {
        try {
            telnet.disconnect();
            telnet = null;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}