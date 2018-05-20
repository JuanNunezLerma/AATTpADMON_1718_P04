import java.security.cert.Certificate;

/**
 * Clase para almacenar los datos de un usuario
 * @author Juan Núñez Lerma / Fernando Cabrera Caballero
 * @version 1.0
 */


public class Usuario {
    private String nombre;
    private String apellido1;
    private String apellido2;
    private String nif;
    private String clavePublica;
    
    /**
     * Constructor
     * @param n Nombre
     * @param a1 Primer apellido
     * @param a2 Segundo apellido
     * @param ni DNI
     */
    public Usuario(String n,String a1,String a2,String ni/*, String clavePublica*/){
        nombre=n;
        apellido1=a1;
        apellido2=a2;
        nif=ni;
        //this.clavePublica=clavePublica;
    }
    
    /**
     * Función toString para imprimir objeto usuario por pantalla
     */
    @Override
    public String toString(){
        return nombre+" "+apellido1+" "+apellido2+" "+nif + "Certificado: "+clavePublica;
    }

    
    /**
     * Getter
     * @return nombre: nombre del usuario
     */
    public String getNombre() {
        return nombre;
    }

    /**
     * Setter
     * @param nombre: nombre del usuario
     */
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    /**
     * Getter
     * @return apellido1: Primer apellido
     */
    public String getApellido1() {
        return apellido1;
    }

    /**
     * Setter
     * @param apellido1: Primer apellido
     */
    public void setApellido1(String apellido1) {
        this.apellido1 = apellido1;
    }

    /**
     * Getter
     * @return apellido2: Segundo apellido
     */
    public String getApellido2() {
        return apellido2;
    }

    /**
     * Setter
     * @param apellido2: Segundo apellido
     */
    public void setApellido2(String apellido2) {
        this.apellido2 = apellido2;
    }

    /**
     * Getter
     * @return nif: DNI de usuario
     */
    public String getNif() {
        return nif;
    }

    /**
     * Setter
     * @param nif: DNI de usuario
     */
    public void setNif(String nif) {
        this.nif = nif;
    }
    
    /**
     * Getter
     * @return clavePublica: Clave Publica de usuario
     */
    public String getClavePublica() {
		return clavePublica;
	}
    
    /**
     * Setter
     * @param clavePublica: Clave Publica de usuario
     */
    public void setClavePublica(String clavePublica) {
    	this.clavePublica=clavePublica;
    }
          
}
