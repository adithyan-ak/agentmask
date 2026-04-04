// This file contains hardcoded secrets that SHOULD be detected
import Stripe from "stripe";

// Stripe live key — should be caught
const stripe = new Stripe("sk_live_51OdEIJ2CtHluikFZ4aNJk8Q");

// Google OAuth secret — should be caught
const GOOGLE_SECRET = "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";
