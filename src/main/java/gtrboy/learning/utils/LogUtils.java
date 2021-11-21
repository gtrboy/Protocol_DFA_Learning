package gtrboy.learning.utils;

public final class LogUtils {
    private LogUtils(){}

    public static void logErrExit(String curclass, String logstr){
        System.out.printf("[%s: %s\n]", curclass, logstr);
        System.exit(-1);
    }
}
