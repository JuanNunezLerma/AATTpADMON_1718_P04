import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

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
        
        try {
	        usuario=user.getNombre();
	        n=usuario.charAt(0);
	        
	        ap1=user.getApellido1();
	        
	        usuario=user.getApellido2();
	        ap2=usuario.charAt(0);
	        
	        nick=n+ap1+ap2;
	        dni=user.getNif();
	        
	        Date fecha = new Date();
	        System.out.println(fecha);
	        String fechaString = fecha.toString();
	        
	        String password=nick+dni+fechaString;
	        MessageDigest sha256=MessageDigest.getInstance("SHA-256");
	        sha256.update(password.getBytes("UTF-8"));
	        String hash=Base64.getEncoder().encodeToString(sha256.digest()); //2bb80d5...527a25b
	        System.out.println(hash);
	        
	        try {
		        PeticionPost post = new PeticionPost ("http://localhost:8081/p3/autentication");
		        post.add("user", nick);
		        post.add("pass", dni);
		        //post.add(propiedad, valor);
		        String respuesta = post.getRespueta();
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
        
    }

