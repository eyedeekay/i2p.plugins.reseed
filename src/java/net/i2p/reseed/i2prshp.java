import java.io.File;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileOutputStream;

// FILE PERMISSIONS
// using Java 7 PosixFilePermission (UNIX only)
// Required for Webservers access (GROUP_READ + OTHERS_READ)
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;

import java.util.Set;
import java.util.HashSet;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.GeneralSecurityException;

import net.i2p.crypto.SigType;
import net.i2p.crypto.SU3File;
import net.i2p.crypto.KeyStoreUtil;
import net.i2p.crypto.CertUtil;

import net.i2p.I2PAppContext;
import net.i2p.router.RouterContext;
import net.i2p.router.networkdb.reseed.ReseedBundler;
import net.i2p.util.SecureFileOutputStream;



public class i2prshp  { 
	private static final String _appname="i2prshp";	
	private static int _state=0;
	private static i2prshp h=null;
    
	private String _configfolder=null;
	private String _configfile=null;
	private	String _jksuser=null;
	private	String _jkspass=null;
	private	String _wwwfolder=null;
	private PrivateKey _privatekey=null;
	
	private static I2PAppContext _appContext=null;
	private static RouterContext _context=null;

	private static final int DEFAULT_SIG_CODE = 6;			
	private static final SigType DEFAULT_SIG_TYPE = SigType.RSA_SHA512_4096;
	private static final String su3_filename = "i2pseeds.su3";

	// 97h with 307 files --> update one su3 every 19 minute
	private static final int max_files=307;								// number of pre-created su3 files
	private static final int max_hours=97;								// max. lifetime of su3 file
	private static final int max_bundle=75;								// number ri per su3 file


   	private boolean fileexist(File f)  {
		boolean r=false;
		try {
			r=f.exists();
		} catch (SecurityException e) { log("error checking file existence " + f + " " + e.getCause()); }
		return r;
	}

    
   	private boolean fileexist(String s)  {
		return fileexist(new File(s));
	}


   	private void filedelete(File f)  {
		try {
			f.delete();
		} catch (SecurityException e) { log("error deleting " + f + " " + e.getCause()); }
	}
	
	
   	private void filedelete(String s)  {
		filedelete(new File(s));
	}
	

	private void filecopy(String s, String t) {
		if (fileexist(s)) {
			try { 
				Files.copy(Paths.get(s), Paths.get(t), StandardCopyOption.REPLACE_EXISTING); 
			} catch (IOException e) { log("error copying " + s + " to " + t + " " + e.getCause()); } 	
			try {
				Path profile = Paths.get(t);
				Set<PosixFilePermission> posixPermissions = new HashSet<PosixFilePermission>();
				posixPermissions.clear();			
				posixPermissions.add(PosixFilePermission.OWNER_READ);
				posixPermissions.add(PosixFilePermission.OWNER_WRITE);
				posixPermissions.add(PosixFilePermission.GROUP_READ);
				posixPermissions.add(PosixFilePermission.OTHERS_READ);
				Files.setPosixFilePermissions(profile, posixPermissions);
			}
			catch (IOException e) { log("error setting permissions on " + t + " " + e.getCause()); } 
		} else { 
			log("file not found: " + s); 
		}
		if (!fileexist(t)) { log("copy from " + s + " to " + t + "failed."); }
	}
	


   	private void error(String s)  {
		_state=0;
		log(s);
		log("--> FATAL ERROR, shutdown ..."); 					
	}


    private static void log(String s) {
		// logging to wrapper log
		try {
			System.out.println("[" + _appname + "] " + s); 
		} catch (SecurityException e) { log("error writing to log + " + e.getCause()); }
	}


    private String getrandom(int n) { 
		// create new username and password 
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz"; 
        StringBuilder sb = new StringBuilder(n); 
        for (int i = 0; i < n; i++) { 
			int index = (int)(AlphaNumericString.length() * Math.random()); 
            sb.append(AlphaNumericString.charAt(index)); 
        } 
        return sb.toString(); 
    } 	
		

   	private String su3_i2s(int i)  {
		return _wwwfolder + String.valueOf(i) + "." + su3_filename;		// index to su3-filename incl. path
	}


   	private boolean su3_exist(int i)  {
		return fileexist(su3_i2s(i));
	}


	private long su3_age(int i) {
		// in seconds
		long r = 0;
		try {
			BasicFileAttributes view = Files.getFileAttributeView(Paths.get(su3_i2s(i)), BasicFileAttributeView.class).readAttributes();		
			r=view.creationTime().toMillis()/1000; 
		} catch (IOException e) { log("error getFileAttributeView " + su3_i2s(i) + " " + e.getCause()); }
		return r;
	}


	private void su3_delete(int i) {
		filedelete(su3_i2s(i));
	}
	
	
	private void su3_create(int i) {	
		String fntarget=su3_i2s(i);
		
		// createZip.createZip
		File fzip = null;		
		ReseedBundler rb = new ReseedBundler(_context);
		try { 
			fzip=rb.createZip(max_bundle);
		} catch (IOException e) { log("error creating ReseedBundler.createZip " + e.getCause()); }					
		if (!fileexist(fzip)) { error("createZip.createZip failed."); return; }
		
		// SU3File.write
		String fnsu3=fzip.getPath() + ".su3";
		SU3File fsu3 = new SU3File(fnsu3);
		try {
			fsu3.write(fzip, SU3File.TYPE_ZIP, SU3File.CONTENT_RESEED, String.valueOf(System.currentTimeMillis()/1000/1000), _jksuser, _privatekey, DEFAULT_SIG_TYPE);
		} catch (IOException e){ log("error creating su3 " + e.getCause());  }
		if (!fileexist(fnsu3)) { error("SU3File.write."); return; }

		// MOVE SU3
		filecopy(fnsu3, fntarget);
		if (fileexist(fzip))  filedelete(fzip);		
		if (fileexist(fnsu3)) filedelete(fnsu3);		
	}	
		

	private void configfile_load() {
		try {		
			_jksuser = Files.readAllLines(Paths.get(_configfile)).get(0);
			_jkspass = Files.readAllLines(Paths.get(_configfile)).get(1);
			_wwwfolder = Files.readAllLines(Paths.get(_configfile)).get(2);
		} catch (IOException e) { error("error reading config " + e.getCause()); return; }
		
		if (_jksuser==null || _jksuser.isEmpty()) { error("empty _jksuser in configfile line 1"); return; }
		if (_jkspass==null || _jkspass.isEmpty()) { error("empty _jkspass in configfile line 2"); return; }
		if (_wwwfolder==null || _wwwfolder.isEmpty()) { error("empty _wwwfolder in configfile line 3"); return; }
		log("config loaded: " + _configfile);
	}

	private void configfile_create() {
		try {
			PrintWriter out = new PrintWriter(_configfile);
			out.println(getrandom(16).toLowerCase() + "@mail.i2p");
			out.println(getrandom(32));
			out.println(_configfolder + _appname + ".www/");
			out.close();
		} catch (IOException e) { error("error writing config " + e.getCause()); }
		if (!fileexist(_configfile)) { error("error writing configfile"); 
		} else { log("new config created: " + _configfile); }
	}

	
	private void configfile() {
		if (!fileexist(_configfile)) {
			log("no configfile found: " + _configfile);
			configfile_create();
		} 
		if (fileexist(_configfile)) {
			configfile_load();
		} else { 
			error("error loading configfile: " + _configfile);
		}
	}
	
  
	private void jks_create(String s)  {
		File ksFile = new File(s);
		try {												
			Object[] rv =  KeyStoreUtil.createKeysAndCRL(ksFile, KeyStoreUtil.DEFAULT_KEYSTORE_PASSWORD, _jksuser, _jksuser, "I2P", 3652, DEFAULT_SIG_TYPE, _jkspass);
			// KeyStoreUtil.java :
				int rv_PublicKey = 0;
				int rv_PrivateKey = 1;
				int rv_X509Certificate = 2;
				int rv_X509CRL = 3;
			CertUtil.saveCert((X509Certificate) rv[rv_X509Certificate], new File(s + ".crt"));
			CertUtil.saveCRL((X509CRL) rv[rv_X509CRL], new File(s + ".crl"));
			FileOutputStream fpriv = new SecureFileOutputStream(new File(s + ".key"));
			KeyStoreUtil.exportPrivateKey(ksFile, KeyStoreUtil.DEFAULT_KEYSTORE_PASSWORD, _jksuser, _jkspass, fpriv);
			fpriv.close();
		} catch (IOException | GeneralSecurityException ex) { error("Error creating jks " + s + " " +ex.getCause()); }
		if (!fileexist(s)) {  error("Error creating jks"); 
		} else { log("new jks created: " + s);	}
	}
	
		
	private void jks_load(String s)  {
		try {
			_privatekey = KeyStoreUtil.getPrivateKey(new File(s),  KeyStoreUtil.DEFAULT_KEYSTORE_PASSWORD, _jksuser, _jkspass);
		} catch (IOException | GeneralSecurityException e) { error("Error loading jks " + e); }
		if (_privatekey==null) {error("Error loading privatekey from jks");
		} else 	{ log("jks and privatekey loaded: " + s); }
	}
		
	
	private void jks() {
		String jksfile=_configfolder + _appname + ".jks";
		if (!fileexist(jksfile)) {
			log("jks not found: " + jksfile);
			jks_create(jksfile);
		} 
		if (fileexist(jksfile)) {
			log("jks found: " + jksfile);
			jks_load(jksfile);
		} else {
			error("error loading jks: " + jksfile);
		}
	}
	
	private void wwwfolder() {
		// create www folder
		try {
			new File(_wwwfolder).mkdirs();
		} catch (SecurityException e) { error("error creating " + _wwwfolder + " " + e.getCause()); }
		if (!fileexist(_wwwfolder)) { error("error creating _wwwfolder: " + _wwwfolder); return; }

		filecopy(_configfolder  + _appname + "/index.php",  _wwwfolder + "/index.php");
		filecopy(_configfolder  + _appname + "/index.html", _wwwfolder + "/index.html");
	}
	
	
	private void worker() {
		while (_state>0) {
			long now=System.currentTimeMillis()/1000;					// unit in seconds
			long scope=max_hours*60*60;
			long age;
			long oldest_v=Long.MAX_VALUE;
			int  oldest_i=0;

			int stat_outdated=0;
			int stat_superfluous=0;
			int stat_missing=0;
			
			for (int i=0; i<max_files*10; i++){							
				if (su3_exist(i)) {
					if (i<max_files) {
						age=su3_age(i);	
						if (age+scope<now) { 							// log("...outdated, refreshing: " + i);
							su3_create(i);		
							stat_outdated++;							
						} else { 
							if (age<=oldest_v) {						// FIND oldest su3
								oldest_v=age;	
								oldest_i=i;
							}
						}
					} else {
						su3_delete(i);									// log("...superfluous, deleting: " + i);
						stat_superfluous++;
					}
				} else {
					if (i<max_files) { 									// log("...missing, recreating: " + i);
							su3_create(i);
							stat_missing++;			
						}	
							
				}
			}
			su3_create(oldest_i); 										// log("...oldest found, refreshing " + oldest_i);
			
			long wait = (long) (((59*59*max_hours) / max_files)/11);	// 59 not 60 ? Yes, to run it a tiny bit faster
			long check=11;												// 11 s slices
			log("su3 files: #" + max_files + ", outdated: #" + stat_outdated + ", superfluous: #" + stat_superfluous + ", missing: #" + stat_missing + ", refreshing oldest: " + oldest_i + ", sleeping: " + (wait*11) + "s ...");	
			for (long i=0; i<wait; i++) {
				try {Thread.sleep(check*1000);} catch(InterruptedException e) { Thread.currentThread().interrupt();}
				if (_state==0) break;
			}
		}
		log("--> stopped."); 					
	}
	
	

    private i2prshp() {
        _appContext = I2PAppContext.getGlobalContext();
        if (_appContext==null) {error("error geting  _appContext"); return; }        
        if (_appContext instanceof RouterContext)
            _context = (RouterContext) _appContext;
        else
            _context = null;
        if (_context==null) {error("error geting  _context"); return; }
           
        _configfolder = _context.getAppDir() + "/plugins/";       
        _configfile = _configfolder + _appname + ".config";
        
        log("configfolder=" + _configfolder);
		log("configfile=" + _configfile);
		configfile();
		if (_state==0) return;
		log("jksuser=" + _jksuser);
		log("jkspass=********" );										// log("jkspass=" + _jkspass);
		log("wwwfolder=" + _wwwfolder);
		jks();
		if (_state==0) return;
		wwwfolder();		
		if (_state==0) return;
		worker();
    }	
	

    public static void main(String args[]) { 
		// -d  .i2p/plugins/i2prshp start
				
		if (args.length != 3 || (!"-d".equals(args[0])))
            throw new IllegalArgumentException("Usage: -d $PLUGIN [start|stop]");
            
		if ("start".equals(args[2])) {
			if (_state==0) {
					log("--> starting up..."); 
					_state=1;
					h = new i2prshp(); 
			} else { 
					log("--> already running.");
			}
		}
		if ("stop".equals(args[2])) {
			if (_state==0) {
					log("--> already stopped."); 
			} else { 
					log("--> stopping ..."); 					
					_state=0;
					h=null;
			}
		}
    } 
} 

