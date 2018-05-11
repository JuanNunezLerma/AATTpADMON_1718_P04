import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.swing.JOptionPane;


/**
 * Aplicaciones Telematicas para la Administración
 * 
 * Este programa debe llevar el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a traves de HTTP 
 * @author Juan Carlos Cuevas Martinez
 */




public class Main{
    /**
     * @param args the command line arguments
     */

    public static void main(String[] args) throws Exception{
    	ByteArrayInputStream bais=null;
        
        //TAREA 2. Conseguir que el metodo LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        if(user!=null)
            System.out.println("usuario: "+user.toString());
        
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
        char n, ap2;
        String ap1;
        String usuario;
        String nick, dni;
        
        String claveServicio = JOptionPane.showInputDialog("Introduce la clave de servicio.");
        
        try {
	        usuario=user.getNombre();
	        n=usuario.charAt(0);
	        
	        ap1=user.getApellido1();
	        
	        usuario=user.getApellido2();
	        ap2=usuario.charAt(0);
	        
	        nick=n+ap1+ap2;
	        dni=user.getNif();
	        String clavePublica=user.getClavePublica();
	        String clavePublicaB64 = Base64.getEncoder().encodeToString(clavePublica.getBytes());	      
	        
	        Date fecha = new Date();
	        System.out.println(fecha);
	        String fechaString = fecha.toString();
	        
	        String hash=nick+dni+fechaString+clavePublica+claveServicio;
	        MessageDigest sha256=MessageDigest.getInstance("SHA-256");
	        sha256.update(hash.getBytes("UTF-8"));
	        String hashB64=Base64.getEncoder().encodeToString(sha256.digest()); //2bb80d5...527a25b
	        System.out.println(hashB64);
	        
	        
	        try {
	        	URL url = new URL("http://localhost:8081/p4/autenticar?nick="+nick+"&dni="+dni+"&fechaString="+fechaString+"&clavePublicaB64="+clavePublicaB64+"&hashB64="+hashB64);
	            URLConnection con = url.openConnection();
	       
	            BufferedReader in = new BufferedReader(
	               new InputStreamReader(con.getInputStream()));
	       
	            String respuesta;
	            while ((respuesta = in.readLine()) != null) {
	               System.out.println(respuesta);
	            }
		       
	            
	        	//PeticionPost post = new PeticionPost ("http://localhost:8081/p4/autenticar");
		        //post.add("user", nick);
		        //post.add("pass", dni);
		        //post.add(propiedad, valor);
		        //String respuesta = post.getRespueta();
		        String respuestaOK = "200 OK";
		        String respuestaBad = "400 BAD REQUEST";
		        
		        if (respuesta.contains(respuestaBad)==true) { //si recibe un 400, mostramos mensaje de usuario incorrecto.
		        	JOptionPane.showMessageDialog(null, "Usuario y contrasena incorrectos. Debe de solicitar su acceso.");
		        }
		        else if (respuesta.contains(respuestaOK)==true) { //si recibe un 200, mostramos mensaje de OK.
		        	JOptionPane.showMessageDialog(null, "Login correcto.");
		        }
		        else {
		        	JOptionPane.showMessageDialog(null, "Error de acceso");
		        }
		        System.out.println(respuesta); 
	        }catch(IOException e) { //Excepcion, por ejemplo, si no esta arrancada la BBDD
	        	 System.out.println("Exception catched: " + e.getMessage());
	        	 JOptionPane.showMessageDialog(null, "Error en el sistema");
	        }  
        }
        catch(Exception e) { //Excepcion por si no se pueden leer DNI o si no se ha introducido DNI en el lector.
        	System.out.println("Exception catched: " + e.getMessage());
        	JOptionPane.showMessageDialog(null, "No ha sido posible leer los datos");
        }
    }
    
	/*public String httpGetSimple(String url){
	    String source = null;
	 
	    HttpClient httpClient = HttpClients.createDefault();
	    HttpGet httpGet = new HttpGet(url);
	    try {
	    HttpResponse httpResponse = httpClient.execute(httpGet);
	        source = EntityUtils.toString(httpResponse.getEntity());
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	    return source;
	}*/
	
	public String conexionGET(String URL, String protocolo) {
	
	    String respuesta = "";
	    BufferedReader rd = null;
	
	    try {
	        URL url = new URL(URL);
	        if (protocolo.equals("HTTPS")) {
	            HttpsURLConnection conn1 = (HttpsURLConnection) url.openConnection();
	            rd = new BufferedReader(new InputStreamReader(conn1.getInputStream()));
	        } else {
	            URLConnection conn2 = url.openConnection();
	            rd = new BufferedReader(new InputStreamReader(conn2.getInputStream()));
	        }
	        String line;
	        while ((line = rd.readLine()) != null) {
	            //Process line...
	            respuesta += line;
	        }
	    } catch (Exception e) {
	        System.out.println("Web request failed");
	    // Web request failed
	    } finally {
	        if (rd != null) {
	            try {
	                rd.close();
	            } catch (IOException ex) {
	                System.out.println("Problema al cerrar el objeto lector");
	            }
	        }
	    }
	    return respuesta;
	}
        
}

