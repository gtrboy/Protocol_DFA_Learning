package gtrboy.learning.utils;

import java.io.InputStream;
import java.io.PrintStream;

import org.apache.commons.net.telnet.TelnetClient;

//import com.telnet.constant.TelnetConstant;

public class TelnetMain {

    private TelnetClient telnet = new TelnetClient("VT100");

    private InputStream in;

    private PrintStream out;

    private static final String DEFAULT_AIX_PROMPT = "#";
    private static final String ENTER_COMMAND_ARROW = ">";
    private static final String ENTER_COMMAND_BRACKETS = "]";
    private static final String ENTER="\n";


    /**
     * telnet 端口
     */
    private String port;

    /**
     * 用户名
     */
    private String user;

    /**
     * 密码
     */
    private String password;

    /**
     * IP 地址
     */
    private String ip;

    public TelnetMain(String ip, String user, String password) {
        this.ip = ip;
        this.port = String.valueOf(23);
        this.user = user;
        this.password = password;
    }

    public TelnetMain(String ip, String port, String user, String password) {
        this.ip = ip;
        this.port = port;
        this.user = user;
        this.password = password;
    }

    public TelnetMain(String ip, String password) {
        this.ip = ip;
        this.port = String.valueOf(23);
        this.password = password;
    }

    /**
     * @return boolean 连接成功返回true，否则返回false
     */
    public boolean connect() {

        boolean isConnect = true;

        try {
            telnet.connect(ip, Integer.parseInt(port));
            in = telnet.getInputStream();
            out = new PrintStream(telnet.getOutputStream());
            telnet.setKeepAlive(true);
            write(password);
            String msg=readUntil(ENTER_COMMAND_ARROW);
            //System.out.println(msg);
            write("en");
            msg=readUntil("Password:");
            //System.out.println(msg);
            //msg=readUntil("\n");
            //System.out.println(msg);
            write(password);
            msg=readUntil(DEFAULT_AIX_PROMPT);
            //System.out.println(msg);
            //msg=readUntil(ENTER_COMMAND_BRACKETS);
            //System.out.println(msg);

        } catch (Exception e) {
            isConnect = false;
            e.printStackTrace();
            return isConnect;
        }
        return isConnect;
    }


    public String readUntil(String pattern) {
        try {
            char lastChar = pattern.charAt(pattern.length() - 1);
            StringBuffer sb = new StringBuffer();
            char ch = (char) in.read();
            while (true) {
                //System.out.print(ch);// ---需要注释掉
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

    public String sendCommand(String command) {
        try {
            write(command);
            return readUntil(DEFAULT_AIX_PROMPT);
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