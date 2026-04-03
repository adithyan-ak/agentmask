// This file contains hardcoded secrets that SHOULD be detected
import Stripe from "stripe";

// Stripe live key — should be caught
const stripe = new Stripe("sk_live_FAKEFAKEFAKEFAKEFAKEFAKE");

// AWS key — should be caught
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// GitHub PAT — should be caught
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";

// Connection string with credentials — should be caught
const DB_URL = "postgresql://admin:s3cr3t_p@ss@db.example.com:5432/myapp";

// Private key — should be caught
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAH...
-----END RSA PRIVATE KEY-----`;

// JWT — should be caught
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
