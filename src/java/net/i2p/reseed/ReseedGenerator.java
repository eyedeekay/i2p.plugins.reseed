package net.i2p.router.web;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.StandardCopyOption;

import java.util.HashSet;
import java.util.Set;

import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.GeneralSecurityException;

import net.i2p.crypto.SU3File;
import net.i2p.crypto.KeyStoreUtil;
import net.i2p.crypto.CertUtil;
import net.i2p.crypto.SigType;
import net.i2p.util.SecureFileOutputStream;
import net.i2p.router.RouterContext;
import net.i2p.router.networkdb.reseed.ReseedBundler;


public class ReseedGenerator extends HelperBase {

/* setings in router.config

# minimal:
reseedbundler.active=true
reseedbundler.email=user@mail.i2p
reseedbundler.password=password
reseedbundler.folder=/var/www/domain.com

# optional, defaults:
reseedbundler.files=300
reseedbundler.hours=72
reseedbundler.bundle=70
reseedbundler.keytype=RSA_SHA512_4096
*/


	private static final int DEFAULT_SIG_CODE = 6;
	private static final String SU3_FILENAME = "i2pseeds.su3";
	private static final int RB_FILEMAX  = 1000;								// Hardcoded max i2pseeds

	private static final String PROP_RB_ACTIVE    = "reseedbundler.active";
	private static final String PROP_RB_EMAIL     = "reseedbundler.email";
	private static final String PROP_RB_PASSWORD  = "reseedbundler.password";
	private static final String PROP_RB_FOLDER    = "reseedbundler.folder";
	private static final String PROP_RB_FILES     = "reseedbundler.files";
	private static final String PROP_RB_HOURS     = "reseedbundler.hours";
	private static final String PROP_RB_BUNDLE    = "reseedbundler.bundle";
	private static final String PROP_RB_KEYTYPE   = "reseedbundler.keytype";

	private boolean RB_ACTIVE;										// active: true false
	private String  RB_EMAIL;										// signing email
	private String  RB_PASSWORD;										// passwort for keystore
	private String  RB_FOLDER_SU3;										// folder for i2pseeds.su3
	private String  RB_KEYTYPE;										// e.g. RSA_SHA512_4096
	private int     RB_FILES;										// number of i2pseeds
	private int     RB_HOURS;										// update window
	private int     RB_BUNDLE;										// ri per i2pseeds
	private String  RB_FOLDER_PRIV;										// .i2p folder
	private String  RB_FILE_JKS;										// java keystore
	private String  RB_FILE_CRT;										// cert
	private String  RB_FILE_CRL;										// cert revocatiopn
	private String  RB_FILE_KEY;										// private pem key
	

	private void create_su3(String su3file, Long now)  {							// CREATE nnn.i2pseeds.su3
	        ReseedBundler rb = new ReseedBundler(_context);
		File f = null;
	
		try { f=rb.createZip(RB_BUNDLE); }								// CREATE ZIP
		catch (IOException e) { System.err.println(e); }

		String stype = RB_KEYTYPE;									// ZIP --> SU3
		String ctype = "reseed";
		String ftype = "ZIP";
		String inputFile = f.toString();
		String signedFile = inputFile + ".su3";
		String privateKeyFile = RB_FILE_JKS;
		String version = String.valueOf(now/1000);
		String signerName = RB_EMAIL;
		String keypw = RB_PASSWORD;
		String kspass = KeyStoreUtil.DEFAULT_KEYSTORE_PASSWORD;
		SU3File.signCLI(stype, ctype, ftype, inputFile, signedFile, privateKeyFile, version, signerName, keypw, kspass);

														// MOVE SU3
		try { Files.move(Paths.get(signedFile), Paths.get(su3file), StandardCopyOption.REPLACE_EXISTING); }
		catch (IOException e) {System.err.println(e);} 

	        if (f != null) f.delete();									// DELETE zip

														// FILE PERMISSIONS
		// using Java 7 PosixFilePermission (UNIX only)
		// Required for Webservers access (GROUP_READ + OTHERS_READ)
		try {
			Path profile = Paths.get(su3file);
			Set<PosixFilePermission> posixPermissions = new HashSet<PosixFilePermission>();
			posixPermissions.clear();			
			posixPermissions.add(PosixFilePermission.OWNER_READ);
			posixPermissions.add(PosixFilePermission.OWNER_WRITE);
			posixPermissions.add(PosixFilePermission.GROUP_READ);
			posixPermissions.add(PosixFilePermission.OTHERS_READ);
			Files.setPosixFilePermissions(profile, posixPermissions);
		}
		catch (IOException e) {System.err.println(e);} 
	}
	

	private long age_su3(String su3file) throws IOException {						// get su3 age
		Path p = Paths.get(su3file);
		BasicFileAttributes view = Files.getFileAttributeView(p, BasicFileAttributeView.class).readAttributes();		
		return view.creationTime().toMillis()/1000; 
	}
	

	private boolean exist(String su3file)  {								// file exists ?
		File f = new File(su3file);
		return f.exists();
	}
	

	private void del_su3(String su3file) throws IOException {						// del su3 file
		Files.delete(Paths.get(su3file));
	}
	

	private void create_jks()  {										// create java keystore
		String RB_FILE_CRT = RB_FOLDER_PRIV + RB_EMAIL + ".crt";
		String RB_FILE_CRL = RB_FOLDER_PRIV + RB_EMAIL + ".crl";
		String RB_FILE_KEY = RB_FOLDER_PRIV + RB_EMAIL + ".key";

		File ksFile = new File(RB_FILE_JKS);
		SigType type = RB_KEYTYPE == null ? SigType.getByCode(Integer.valueOf(DEFAULT_SIG_CODE)) : SigType.parseSigType(RB_KEYTYPE);
		if (type == null) { System.out.println("Signature type " + RB_KEYTYPE + " is not supported"); }
		String kspass = KeyStoreUtil.DEFAULT_KEYSTORE_PASSWORD;
		String alias = RB_EMAIL;
		String keypw = RB_PASSWORD;
		try {												// JKS
			Object[] rv =  KeyStoreUtil.createKeysAndCRL(ksFile, kspass, alias, alias, "I2P", 3652, type, keypw);
			File fcrt = new File(RB_FILE_CRT);							// CRT
			CertUtil.saveCert((X509Certificate) rv[2], fcrt);
			File fcrl = new File(RB_FILE_CRL);							// CRL
			CertUtil.saveCRL((X509CRL) rv[3], fcrl);
			FileOutputStream fpriv = new SecureFileOutputStream(new File(RB_FILE_KEY));		// KEY/PEM
			KeyStoreUtil.exportPrivateKey(ksFile, kspass, alias, keypw, fpriv);
			fpriv.close();
		}	
		catch (GeneralSecurityException gse) { System.err.println("Error creating keys"); }
		catch (IOException ioe) { System.err.println("Error creating keys for " + alias); }
	}


	public File createZip() throws IOException {								// MAIN

	        RB_ACTIVE      = _context.getProperty(PROP_RB_ACTIVE, false);
		if (! RB_ACTIVE) return null;									// EXIT if not active

		RB_EMAIL       = _context.getProperty(PROP_RB_EMAIL,    "user@mail.i2p");
		RB_PASSWORD    = _context.getProperty(PROP_RB_PASSWORD, "password");
		RB_FOLDER_SU3  = _context.getProperty(PROP_RB_FOLDER,   "/var/www/domain.com");
		RB_FILES       = _context.getProperty(PROP_RB_FILES,    300);
		RB_HOURS       = _context.getProperty(PROP_RB_HOURS,    72);
		RB_BUNDLE      = _context.getProperty(PROP_RB_BUNDLE,   70);
		RB_KEYTYPE     = _context.getProperty(PROP_RB_KEYTYPE,  "RSA_SHA512_4096");
		RB_FOLDER_PRIV = _context.getConfigDir().toString() + File.separatorChar;
		RB_FILE_JKS    = RB_FOLDER_PRIV + RB_EMAIL + ".jks";						// JKS in .i2p folder

		long end = RB_HOURS*60*60;
		if (!exist(RB_FILE_JKS)) create_jks();								// CREATE JKS if missing
	
		while (RB_ACTIVE) {										// MAIN LOOP
			long now=System.currentTimeMillis()/1000;
			long age=0;
			long oldest=Long.MAX_VALUE;
			String oldestf = RB_FOLDER_SU3 + File.separatorChar + "0." + SU3_FILENAME;		// DEFAULT oldest

			for(int i=0; i<RB_FILEMAX; i++){							
				String su3file = RB_FOLDER_SU3 + File.separatorChar + String.valueOf(i) + "." + SU3_FILENAME;
				if (exist(su3file)) {
					if (i<RB_FILES) {
						age=age_su3(su3file);	
						if (now>age+end) { 						// OUTDATED su3
							create_su3(su3file, now);		
						} else { 
							if (age<=oldest) {					// FIND oldest su3
								oldest=age;	
								oldestf=su3file;
							}
						}
					} else {
						del_su3(su3file);						// TOO MANY su3
					}
				} else {
					if (i<RB_FILES) create_su3(su3file, now);				// MISSING su3
				}
			}
			create_su3(oldestf, now); 								// UPDATE oldest su3

			// 59 not 60 ? Yes, to make it a tiny bit faster
			int wait = (int) ((59*59*RB_HOURS) / RB_FILES);						// SLEEP
			try {Thread.sleep(wait*1000);} catch(InterruptedException e) { Thread.currentThread().interrupt();}

		        RB_ACTIVE = _context.getProperty(PROP_RB_ACTIVE, false);				// EXIT Switch
		}
	return null;
	}
}


