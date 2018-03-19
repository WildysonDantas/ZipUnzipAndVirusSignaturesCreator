
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.swing.JOptionPane;
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
	//Aqui vocï¿½ deve extrair da classe  Componente_03_VirusScanningServer.java a parte que se refere ï¿½ criaï¿½ï¿½o de assinaturas.

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
   
    
     
    
    public static void Servirdor1() throws IOException{
        
        
		String arquivo = System.getProperty("user.dir") + "/VirusDoCliente.zip";

       
        ServerSocket sv = new ServerSocket(6001);

	    while(true){
	        JOptionPane.showMessageDialog(null, "Conectado a porta 6001\nAguardando conexao...");

	        System.out.println("Conectado a porta 6001\n");
	        Socket sk = sv.accept();
	        DataInputStream msgDoCliente = new DataInputStream(sk.getInputStream());
	       // ZipInputStream  zis = new ZipInputStream(new BufferedInputStream(msgDoCliente));
	       //;
	        
	        try{
	        	compactarParaZip(arquivo, msgDoCliente );
	        	JOptionPane.showMessageDialog(null, "Arquivo Recebido com sucesso\n Iniciando a descompactação...");
	        	Descompactar(arquivo);
	        	
	        }catch(Exception e){
	        	JOptionPane.showMessageDialog(null, "Ocorreu um erro na descompactação do arquivo");
	        }
	        
	        try{
	        	JOptionPane.showMessageDialog(null, "Criando as assinaturas de virus...");
		        initSignatureDB(VIRUS_DB_PATH);
	        }catch(Exception e){
	        	JOptionPane.showMessageDialog(null, "Erro ao criar assinaturas de virus...");
	        }
	       
	        try{
	        	 JOptionPane.showMessageDialog(null, "Estabelecendo conexão com a maquina 3...");
	        	Socket sk2 = new Socket("25.37.182.144",6000);
	 	        ObjectOutputStream l = new ObjectOutputStream(sk2.getOutputStream());            
	           l.writeObject(signatureDB);
	           JOptionPane.showMessageDialog(null, "Arquivos enviados para a maquina 3...");
	            sk2.close();

	        }catch(IOException e){
		        JOptionPane.showMessageDialog(null, "Falha ao estabelecer conexão com a maquina 3...");

	        }
	        sk.close();

	        
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
           // JOptionPane.showMessageDialog(null, "Arquivo Recebido com sucesso\n Iniciando a descompactação...");

        try {
			// Caminho do arquivo ZIP
        	String zipFile = arquivo;
        	String pastaDestino = System.getProperty("user.dir") + "\\DBVirus\\";
 
			File file = new File(pastaDestino);
 
			// Se nÃ£o existir a pasta destino
			// serÃ¡ criada por nosso programa
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
