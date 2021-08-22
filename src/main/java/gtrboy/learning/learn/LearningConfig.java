package gtrboy.learning.learn;

import java.net.InetAddress;

public interface LearningConfig {

    InetAddress getServerAddress();

    Integer getPort();

    Integer getTimeout();
}
