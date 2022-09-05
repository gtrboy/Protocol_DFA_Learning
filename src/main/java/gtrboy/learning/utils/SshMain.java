package gtrboy.learning.utils;

import com.jcraft.jsch.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class SshMain {
    private String host;
    private String username;
    private String password;
    private String sul;
    private int port = 22;
    private int timeout = 60 * 60 * 1000;
    private Session session = null;
    private ChannelShell channelShell = null;

    // SonicWall pre cmds
    private List<String> sw_pre_cmds = Arrays.asList(
            "config", "vpn policy site-to-site \"ipsec-test\""
    );

    //SonicWall reset cmds
    private static List<String> sw_cmds = Arrays.asList(
            "no enable", "commit", "enable", "commit"
    );

    public SshMain(String host, String username, String password, String sul) {
        this.host = host;
        this.username = username;
        this.password = password;
        this.sul = sul;
    }

    public void openSession(){
        JSch jSch = new JSch();
        try {
            session = jSch.getSession(username, host, port);
            session.setPassword(password);
            session.setTimeout(timeout);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();

            channelShell = (ChannelShell) session.openChannel("shell");
            channelShell.connect();

            if(sul.equals("sonicwall")) {
                execCommand(sw_pre_cmds);
            }
            else{
                System.out.println("No such device!");
                System.exit(-1);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void resetSW(){
        execCommand(sw_cmds);
    }

    public void execCommand(List<String> cmds) {
        try {
            InputStream is = channelShell.getInputStream();
            OutputStream os = channelShell.getOutputStream();

            for (String cmd : cmds){
                os.write((cmd + "\n\r").getBytes());
                os.flush();
                byte[] tmp = new byte[1024];
                while (true) {
                    while (is.available() > 0) {
                        //System.out.println("have data.");
                        int i = is.read(tmp, 0, 1024);
                        if (i < 0)
                            break;
                        //System.out.println(new String(tmp, 0, i));
                    }
                    //TimeUnit.SECONDS.sleep(1);
                    if (channelShell.isClosed()) {
                        if (is.available() > 0)
                            continue;
                        //System.out.println("exit-status: " + channelShell.getExitStatus());
                        break;
                    }
                    break;
                    // inputStream.close();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        // return runLog.toString();
    }

    public void close(){
        if(session.isConnected()){
            session.disconnect();
            session = null;
        }
        if(channelShell.isConnected()){
            channelShell.disconnect();
            channelShell = null;
        }
    }


}