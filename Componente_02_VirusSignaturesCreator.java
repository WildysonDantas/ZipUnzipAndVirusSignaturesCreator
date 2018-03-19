
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Componente_02_VirusSignaturesCreator  {
	static final int TAMANHO_BUFFER = 4096;
	private static String[] signatureDB;
	private static int SIGNATURE_SIZE=1348;
        private static String VIRUS_DB_PATH= System.getProperty("user.dir") + "\\DBVirus\\";

        private static final int BUFFER = 2048;
        
        public static void main(String [] args) throws IOException{
            Servirdor1(); 
           
        }         
                 
     
        
        
	public static void initSignatureDB(String pathToSignatures) {
		System.out.println("Started signature initialization on folder: "
				+ VIRUS_DB_PATH);
		System.out.println("Finished signature initialization");
                try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			File signatureFolder = new File(pathToSignatures);
			File[] demoViruses = signatureFolder.listFiles();

			signatureDB = new String[demoViruses.length];
			char[] buffer = new char[getSIGNATURE_SIZE()];

			int i = 0;
			for (File virus : demoViruses) {

				FileReader signatureFile = new FileReader(virus);
				int totalRead = 0;
				int read = signatureFile.read(buffer, totalRead, buffer.length - totalRead);
				signatureDB[i++] = byteArrayToHexString(md.digest(new String(
						buffer).getBytes()));
				signatureFile.close();
			}

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException " + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Exception " + e.getMessage());
		}
	}


	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
	//Aqui voc� deve extrair da classe  Componente_03_VirusScanningServer.java a parte que se refere � cria��o de assinaturas.

    /**
     * @return the signatureDB
     */
    public String[] getSignatureDB() {
        return signatureDB;
    }

    /**
     * @return the SIGNATURE_SIZE
     */
    public static int getSIGNATURE_SIZE() {
        return SIGNATURE_SIZE;
    }

    /**
     * @param SIGNATURE_SIZE the SIGNATURE_SIZE to set
     */
    public void setSIGNATURE_SIZE(int SIGNATURE_SIZE) {
        this.SIGNATURE_SIZE = SIGNATURE_SIZE;
    }

    /**
     * @param VIRUS_DB_PATH the VIRUS_DB_PATH to set
     */
    public void setVIRUS_DB_PATH(String VIRUS_DB_PATH) {
        this.VIRUS_DB_PATH = VIRUS_DB_PATH;
    }
    
     
    
    public static void Servirdor1() throws IOException{
        
        
		String arquivo = System.getProperty("user.dir") + "/VirusDoCliente.zip";

        String login,senha;
        ServerSocket sv = new ServerSocket(6001);

	    while(true){
	        System.out.println("Conectado a porta 6000");
	        Socket sk = sv.accept();
	        DataInputStream msgDoCliente = new DataInputStream(sk.getInputStream());
	       // ZipInputStream  zis = new ZipInputStream(new BufferedInputStream(msgDoCliente));
	       //;
	        compactarParaZip(arquivo, msgDoCliente );
	        Descompactar(arquivo);
	        System.out.println("ok");
	        initSignatureDB(VIRUS_DB_PATH);
	        System.out.println(signatureDB);
	        
	        
	        Socket sk2 = new Socket("25.37.182.144",6000);
	        ObjectOutputStream l = new ObjectOutputStream(sk2.getOutputStream());            
          l.writeObject(signatureDB);
	
            sk2.close();
            
	        
	    }
                
                    
    }
    
    
    
    public static void compactarParaZip( String arquivoCompactado, DataInputStream arquivo)throws IOException {

		 try {
	           	FileOutputStream destino = new FileOutputStream(new File(arquivoCompactado));
	            ZipOutputStream saida = new ZipOutputStream(new BufferedOutputStream(destino));
	            //File file = new File(arquivo);
	            //FileInputStream streamDeEntrada = new FileInputStream(arquivo);
	            BufferedInputStream origem = new BufferedInputStream(arquivo, TAMANHO_BUFFER);
	            ZipEntry entry = new ZipEntry("virusDoCliente.bin");
	            saida.putNextEntry(entry);
	                       
	            int cont;
				byte[] dados = new byte[TAMANHO_BUFFER];
				while((cont = origem.read(dados , 0, TAMANHO_BUFFER)) != -1) {
	                saida.write(dados, 0, cont);
	            }
	            origem.close();
	            saida.close();
	        } catch(IOException e) {
	            throw new IOException(e.getMessage());
	        }
	   
	 
}
    
    
                
        public static void Descompactar(String arquivo) throws IOException{
        // Abre o arquivo .zip
        //File arquivoZip = new File(caminho+"/Virus.zip");
 
        try {
			// Caminho do arquivo ZIP
        	String zipFile = arquivo;
        	String pastaDestino = System.getProperty("user.dir") + "\\DBVirus\\";
 
			File file = new File(pastaDestino);
 
			// Se não existir a pasta destino
			// será criada por nosso programa
			if (file.exists() == false) {
				file.mkdirs();
			}
 
			BufferedOutputStream dest = null;
			FileInputStream fis = new FileInputStream(zipFile);
			ZipInputStream zis = new ZipInputStream(
					new BufferedInputStream(fis));
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				System.out.println("Extraindo o arquivo: " + entry);
				int count;
				byte data[] = new byte[BUFFER];
				// Cria os arquivos no disco
				FileOutputStream fos = new FileOutputStream(pastaDestino + entry.getName());
				dest = new BufferedOutputStream(fos, BUFFER);
				while ((count = zis.read(data, 0, BUFFER)) != -1) {
					dest.write(data, 0, count);
				}
				dest.flush();
				dest.close();
			}
			zis.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
            
           
       
    }
}
