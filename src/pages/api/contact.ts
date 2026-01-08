import type { APIContext } from "astro";
import { createMimeMessage } from "mimetext";

interface ContactFormData {
  name: string;
  email: string;
  message: string;
  turnstileToken: string;
}

interface TurnstileResponse {
  success: boolean;
  "error-codes"?: string[];
}

function validateFormData(data: unknown): ContactFormData | null {
  if (!data || typeof data !== "object") return null;

  const { name, email, message, turnstileToken } = data as Record<
    string,
    unknown
  >;

  if (
    typeof name !== "string" ||
    name.trim().length < 2 ||
    typeof email !== "string" ||
    !email.includes("@") ||
    typeof message !== "string" ||
    message.trim().length < 10 ||
    typeof turnstileToken !== "string" ||
    !turnstileToken
  ) {
    return null;
  }

  return {
    name: name.trim(),
    email: email.trim(),
    message: message.trim(),
    turnstileToken,
  };
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export async function POST(context: APIContext) {
  try {
    const env = context.locals.runtime.env as {
      TURNSTILE_SECRET_KEY?: string;
      CONTACT_EMAIL?: { send: (message: EmailMessage) => Promise<void> };
    };

    if (!env.TURNSTILE_SECRET_KEY) {
      console.error("TURNSTILE_SECRET_KEY not configured");
      return new Response(
        JSON.stringify({ success: false, error: "Server configuration error" }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!env.CONTACT_EMAIL) {
      console.error("CONTACT_EMAIL binding not configured");
      return new Response(
        JSON.stringify({ success: false, error: "Server configuration error" }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    let body: unknown;
    try {
      body = await context.request.json();
    } catch {
      return new Response(
        JSON.stringify({ success: false, error: "Invalid JSON" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    const formData = validateFormData(body);
    if (!formData) {
      return new Response(
        JSON.stringify({
          success: false,
          error: "Invalid form data. Please check all fields.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Verify Turnstile token
    const turnstileResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: formData.turnstileToken,
        }),
      }
    );

    const turnstileResult = (await turnstileResponse.json()) as TurnstileResponse;
    if (!turnstileResult.success) {
      console.error("Turnstile verification failed:", turnstileResult["error-codes"]);
      return new Response(
        JSON.stringify({
          success: false,
          error: "Bot verification failed. Please try again.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Construct MIME message
    const msg = createMimeMessage();
    msg.setSender({ name: "Contact Form", addr: "noreply@bcnelson.dev" });
    msg.setRecipient("bradley@nel.family");
    msg.setHeader("Reply-To", formData.email);
    msg.setSubject(`New Contact Form Submission from ${formData.name}`);

    const htmlBody = `
<h2>New Contact Form Submission</h2>
<p><strong>Name:</strong> ${escapeHtml(formData.name)}</p>
<p><strong>Email:</strong> ${escapeHtml(formData.email)}</p>
<p><strong>Message:</strong></p>
<p>${escapeHtml(formData.message).replace(/\n/g, "<br>")}</p>
<hr>
<p style="color: #666; font-size: 12px;">Sent from bcnelson.dev contact form</p>
    `.trim();

    const textBody = `
New Contact Form Submission

Name: ${formData.name}
Email: ${formData.email}

Message:
${formData.message}

---
Sent from bcnelson.dev contact form
    `.trim();

    msg.addMessage({
      contentType: "text/plain",
      data: textBody,
    });
    msg.addMessage({
      contentType: "text/html",
      data: htmlBody,
    });

    // Send email using Cloudflare Email Routing
    const { EmailMessage } = await import("cloudflare:email");
    const emailMessage = new EmailMessage(
      "noreply@bcnelson.dev",
      "bradley@nel.family",
      msg.asRaw()
    );
    await env.CONTACT_EMAIL.send(emailMessage);

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Contact form error:", err);
    return new Response(
      JSON.stringify({ success: false, error: "Failed to send message" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}

export async function GET() {
  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { "Content-Type": "application/json" },
  });
}
