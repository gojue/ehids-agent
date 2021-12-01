import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        String [] arrCmd = {"ifconfig -s","ping www.qq.com", "uname -a", "ps -ef", "w", "date"};
        while (true) {
            try {
                int index=(int)(Math.random()*arrCmd.length);
                String randCmd = arrCmd[index];
                System.out.println("start to exec :"+ randCmd);
                Runtime.getRuntime().exec(randCmd);
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                Thread.sleep(10 * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
