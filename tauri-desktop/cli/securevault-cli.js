#!/usr/bin/env node

/**
 * SecureVault CLI - Command Line Interface
 * Permet d'ajouter des fichiers au coffre-fort depuis la ligne de commande
 */

const { invoke } = require("@tauri-apps/api/tauri");
const fs = require("fs").promises;
const path = require("path");
const readline = require("readline");

// Créer interface readline pour input utilisateur
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Prompt async
const question = (query) =>
  new Promise((resolve) => rl.question(query, resolve));

// Couleurs console
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

const log = {
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  error: (msg) => console.error(`${colors.red}✗${colors.reset} ${msg}`),
  warn: (msg) => console.warn(`${colors.yellow}⚠${colors.reset} ${msg}`),
  title: (msg) =>
    console.log(`\n${colors.cyan}${colors.bright}${msg}${colors.reset}\n`),
};

class SecureVaultCLI {
  constructor() {
    this.authenticated = false;
    this.username = null;
  }

  async login() {
    log.title("🔐 SecureVault CLI - Authentification");

    const username = await question("Nom d'utilisateur: ");
    const password = await question("Mot de passe: ");

    try {
      // Appeler la commande Tauri de login
      const result = await invoke("login", { username, password });

      if (result.success) {
        this.authenticated = true;
        this.username = username;
        log.success(`Connecté en tant que ${username}`);
        return true;
      } else {
        log.error("Échec de l'authentification");
        return false;
      }
    } catch (error) {
      log.error(`Erreur d'authentification: ${error}`);
      return false;
    }
  }

  async addFile(filePath) {
    if (!this.authenticated) {
      log.error("Vous devez vous connecter d'abord");
      return false;
    }

    try {
      // Vérifier que le fichier existe
      const stats = await fs.stat(filePath);

      if (!stats.isFile()) {
        log.error("Le chemin spécifié n'est pas un fichier");
        return false;
      }

      log.info(`Ajout du fichier: ${path.basename(filePath)}`);
      log.info(`Taille: ${this.formatFileSize(stats.size)}`);

      // Lire le fichier
      const fileBuffer = await fs.readFile(filePath);
      const fileData = fileBuffer.toString("base64");
      const filename = path.basename(filePath);

      // Appeler la commande Tauri pour créer le fichier sécurisé
      const result = await invoke("create_secure_file", {
        filename,
        fileData,
      });

      if (result.success) {
        log.success(`Fichier ajouté avec succès! ID: ${result.file_id}`);
        log.info(`Le fichier a été chiffré et stocké en sécurité`);
        return true;
      } else {
        log.error("Échec de l'ajout du fichier");
        return false;
      }
    } catch (error) {
      log.error(`Erreur lors de l'ajout du fichier: ${error.message}`);
      return false;
    }
  }

  async listFiles() {
    if (!this.authenticated) {
      log.error("Vous devez vous connecter d'abord");
      return;
    }

    try {
      const files = await invoke("get_secure_files");

      if (files.length === 0) {
        log.info("Aucun fichier dans le coffre-fort");
        return;
      }

      log.title("📁 Fichiers dans le coffre-fort:");

      files.forEach((file, index) => {
        console.log(`${index + 1}. ${file.filename}`);
        console.log(`   ID: ${file.id}`);
        console.log(`   Taille: ${this.formatFileSize(file.file_size)}`);
        console.log(`   Date: ${new Date(file.created_at).toLocaleString()}`);
        console.log("");
      });
    } catch (error) {
      log.error(`Erreur lors de la récupération des fichiers: ${error}`);
    }
  }

  async addPassword() {
    if (!this.authenticated) {
      log.error("Vous devez vous connecter d'abord");
      return false;
    }

    log.title("🔑 Ajouter un mot de passe");

    const title = await question("Titre: ");
    const username = await question("Nom d'utilisateur: ");
    const password = await question("Mot de passe: ");
    const url = await question("URL (optionnel): ");
    const category = await question("Catégorie (optionnel): ");

    try {
      const result = await invoke("create_password", {
        title,
        username: username || undefined,
        password,
        url: url || undefined,
        category: category || undefined,
      });

      if (result.success) {
        log.success("Mot de passe ajouté avec succès!");
        return true;
      } else {
        log.error("Échec de l'ajout du mot de passe");
        return false;
      }
    } catch (error) {
      log.error(`Erreur: ${error}`);
      return false;
    }
  }

  formatFileSize(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  }

  printHelp() {
    log.title("📖 SecureVault CLI - Aide");
    console.log("Commandes disponibles:");
    console.log("");
    console.log("  add <fichier>      Ajouter un fichier au coffre-fort");
    console.log("  add-password       Ajouter un mot de passe");
    console.log("  list              Lister tous les fichiers");
    console.log("  help              Afficher cette aide");
    console.log("  exit              Quitter");
    console.log("");
    console.log("Exemples:");
    console.log("  securevault-cli add /path/to/document.pdf");
    console.log("  securevault-cli add-password");
    console.log("  securevault-cli list");
    console.log("");
  }

  async run(args) {
    // Authentification d'abord
    const loginSuccess = await this.login();

    if (!loginSuccess) {
      rl.close();
      process.exit(1);
    }

    // Si pas d'arguments, mode interactif
    if (args.length === 0) {
      await this.interactiveMode();
      return;
    }

    // Traiter la commande
    const command = args[0];

    switch (command) {
      case "add":
        if (args.length < 2) {
          log.error("Usage: add <chemin-fichier>");
          break;
        }
        await this.addFile(args[1]);
        break;

      case "add-password":
        await this.addPassword();
        break;

      case "list":
        await this.listFiles();
        break;

      case "help":
        this.printHelp();
        break;

      default:
        log.error(`Commande inconnue: ${command}`);
        this.printHelp();
    }

    rl.close();
  }

  async interactiveMode() {
    log.title("🔐 SecureVault CLI - Mode Interactif");
    console.log('Tapez "help" pour voir les commandes disponibles');
    console.log("");

    const processCommand = async () => {
      const input = await question("securevault> ");
      const parts = input.trim().split(" ");
      const command = parts[0];

      if (command === "exit" || command === "quit") {
        log.info("Au revoir!");
        rl.close();
        process.exit(0);
      }

      switch (command) {
        case "add":
          if (parts.length < 2) {
            log.error("Usage: add <chemin-fichier>");
          } else {
            await this.addFile(parts[1]);
          }
          break;

        case "add-password":
          await this.addPassword();
          break;

        case "list":
          await this.listFiles();
          break;

        case "help":
          this.printHelp();
          break;

        case "":
          break;

        default:
          log.error(`Commande inconnue: ${command}`);
      }

      // Boucle suivante
      processCommand();
    };

    processCommand();
  }
}

// Point d'entrée
async function main() {
  const args = process.argv.slice(2);
  const cli = new SecureVaultCLI();

  try {
    await cli.run(args);
  } catch (error) {
    log.error(`Erreur fatale: ${error.message}`);
    process.exit(1);
  }
}

// Gérer Ctrl+C
process.on("SIGINT", () => {
  console.log("\n");
  log.info("Interruption par l'utilisateur");
  rl.close();
  process.exit(0);
});

main();
