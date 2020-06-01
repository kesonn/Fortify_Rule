import java.io.*;
import static com.fortify.util.CryptoUtil.decryptCompressed;

public class FortifyRuleDecrypter {
    private String ruleDir;
    private String saveDir;

    FortifyRuleDecrypter(String ruleDir,String saveDir){
        this.ruleDir = ruleDir;
        this.saveDir = saveDir;
    }

    public  void doDecrypt(){
        File encryptRule = new File(ruleDir);
        // 传入的是文件
        if(encryptRule.isFile()) {
            if(encryptRule.getName().endsWith(".bin")) {
                decryptRule(encryptRule, new File(saveDir + File.separator + encryptRule.getName() + ".xml"));
            }else{
                System.out.println("[-] The rule file suffix is.bin!");
                System.exit(0);
            }
        }

        //传入是目录
        if (encryptRule.isDirectory()) {
            File[] listFile = encryptRule.listFiles();
            for(File file:listFile){
                if(file.getName().endsWith(".bin")){
                    File saveName = new File(saveDir + File.separator + file.getName().replace(".bin","") + ".xml");
                    decryptRule(file,saveName);
                }
            }
        }

    }

    public  void decryptRule(File encFile, File decFile){
        try {
            //调用decryptCompressed()对规则库进行解密
            InputStream ruleStream = decryptCompressed(new FileInputStream(encFile), null);
            OutputStream outputStream = new FileOutputStream(decFile);
            byte[] b = new byte[1024];
            while ((ruleStream.read(b)) != -1) {
                outputStream.write(b);
            }
            ruleStream.close();
            outputStream.close();
            System.out.println(String.format("[+] success %s -> %s",encFile.getName(),decFile.getAbsolutePath()));
        }catch (Exception e){
            System.out.println(String.format("[-] fail %s -> %s",encFile.getName(),decFile.getAbsolutePath()));
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        if(args.length != 2){
            System.out.println("Usage: java -jar FortifyRuleDecrypter.jar [rule_dir|rule_file] <save_dir>");
            System.exit(0);
        }
        FortifyRuleDecrypter decrypter = new FortifyRuleDecrypter(args[0],args[1]);
        decrypter.doDecrypt();
    }
}