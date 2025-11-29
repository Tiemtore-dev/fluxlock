use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::time::Duration;

fn main() {
    println!("🧪 Test d'envoi d'email SMTP\n");
    
    // Configuration depuis .env
    let smtp_host = "smtp.gmail.com";
    let smtp_port = 587;
    let smtp_username = "tiemtorenahalfa@gmail.com";
    let smtp_password = "evcf yyjn vizc ctka";
    let from_email = "noreply@securevault.com";
    let from_name = "SecureVault Security";
    let to_email = "tiemtorenahalfa@gmail.com";
    
    println!("📧 Configuration:");
    println!("   Host: {}", smtp_host);
    println!("   Port: {}", smtp_port);
    println!("   Username: {}", smtp_username);
    println!("   From: {} <{}>", from_name, from_email);
    println!("   To: {}", to_email);
    println!();
    
    // Vérifier la connexion Internet
    println!("🌐 Test de connexion Internet...");
    match std::net::TcpStream::connect_timeout(
        &format!("8.8.8.8:53").parse().unwrap(),
        Duration::from_secs(3)
    ) {
        Ok(_) => println!("   ✅ Connexion Internet OK\n"),
        Err(e) => {
            println!("   ❌ Pas de connexion Internet: {}\n", e);
            return;
        }
    }
    
    // Générer le contenu de l'email
    let subject = "🔐 Test SecureVault - Code OTP";
    let code = "123456";
    
    let html_body = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #2563eb; margin-bottom: 30px; }}
        .code-box {{ background-color: #eff6ff; border: 2px solid #2563eb; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }}
        .code {{ font-size: 36px; font-weight: bold; color: #1e40af; letter-spacing: 8px; font-family: monospace; }}
        .info {{ color: #6b7280; font-size: 14px; margin-top: 20px; }}
        .footer {{ text-align: center; color: #9ca3af; font-size: 12px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SecureVault</h1>
            <h2>Code de Vérification OTP</h2>
        </div>
        
        <p>Bonjour,</p>
        <p>Voici votre code de vérification à usage unique (OTP) :</p>
        
        <div class="code-box">
            <div class="code">{}</div>
        </div>
        
        <div class="info">
            ⏱️ Ce code est valide pendant <strong>30 secondes</strong>.<br>
            🔒 Ne partagez jamais ce code avec qui que ce soit.<br>
            ❌ Si vous n'avez pas demandé ce code, ignorez cet email.
        </div>
        
        <div class="footer">
            <p>Cet email a été envoyé automatiquement par SecureVault.<br>
            Ne répondez pas à ce message.</p>
        </div>
    </div>
</body>
</html>
    "#, code);
    
    let text_body = format!(r#"
🔐 SecureVault - Code de Vérification OTP

Bonjour,

Voici votre code de vérification à usage unique (OTP) :

    {}

⏱️ Ce code est valide pendant 30 secondes.
🔒 Ne partagez jamais ce code avec qui que ce soit.
❌ Si vous n'avez pas demandé ce code, ignorez cet email.

---
Cet email a été envoyé automatiquement par SecureVault.
    "#, code);
    
    // Construire le message
    println!("📝 Construction du message email...");
    let email = match Message::builder()
        .from(format!("{} <{}>", from_name, from_email).parse().unwrap())
        .to(to_email.parse().unwrap())
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        ) {
        Ok(msg) => {
            println!("   ✅ Message construit avec succès\n");
            msg
        }
        Err(e) => {
            println!("   ❌ Erreur construction message: {}\n", e);
            return;
        }
    };
    
    // Configurer SMTP avec STARTTLS
    println!("🔌 Connexion au serveur SMTP...");
    let creds = Credentials::new(
        smtp_username.to_string(),
        smtp_password.to_string(),
    );
    
    let mailer = match SmtpTransport::starttls_relay(smtp_host) {
        Ok(transport) => {
            println!("   ✅ Relay SMTP configuré\n");
            transport
                .credentials(creds)
                .port(smtp_port)
                .timeout(Some(Duration::from_secs(30)))
                .build()
        }
        Err(e) => {
            println!("   ❌ Erreur configuration SMTP: {}\n", e);
            return;
        }
    };
    
    // Envoyer l'email
    println!("📤 Envoi de l'email...");
    match mailer.send(&email) {
        Ok(response) => {
            println!("   ✅ Email envoyé avec succès !");
            println!("   📊 Réponse serveur: {:?}\n", response);
            println!("🎉 Test réussi ! Vérifiez votre boîte de réception.");
        }
        Err(e) => {
            println!("   ❌ Erreur lors de l'envoi: {}\n", e);
            println!("💡 Vérifications à faire:");
            println!("   1. Le mot de passe d'application Gmail est correct");
            println!("   2. L'authentification à 2 facteurs est activée sur Gmail");
            println!("   3. Le pare-feu n'est pas en train de bloquer le port 587");
            println!("   4. L'adresse email est valide");
        }
    }
}
