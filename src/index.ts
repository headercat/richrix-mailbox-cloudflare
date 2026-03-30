interface Env {
    MAILBOX_ENDPOINT: string;
    MAILBOX_SECRET: string;
}

async function hmacSha256(message: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return Array.from(new Uint8Array(signature))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export default {
    async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
        const rawEmail = await new Response(message.raw).text();

        const headers: Record<string, string> = {};
        for (const [key, value] of message.headers.entries()) {
            headers[key.toLowerCase()] = value;
        }

        const contentType = headers['content-type'] ?? '';
        let bodyHtml = '';
        let bodyText = '';

        if (contentType.includes('multipart/')) {
            const boundary = (contentType.match(/boundary="?([^";]+)"?/) ?? [])[1] ?? '';
            if (boundary) {
                const parts = rawEmail.split(`--${boundary}`);
                for (const part of parts) {
                    const partLower = part.toLowerCase();
                    if (partLower.includes('content-type: text/html')) {
                        bodyHtml = part.replace(/^.*?\r\n\r\n/s, '').replace(/--$/, '').trim();
                    } else if (partLower.includes('content-type: text/plain')) {
                        bodyText = part.replace(/^.*?\r\n\r\n/s, '').replace(/--$/, '').trim();
                    }
                }
            }
        } else if (contentType.includes('text/html')) {
            bodyHtml = rawEmail.replace(/^.*?\r\n\r\n/s, '').trim();
        } else {
            bodyText = rawEmail.replace(/^.*?\r\n\r\n/s, '').trim();
        }

        const payload = JSON.stringify({
            from: headers['from'] ?? message.from ?? '',
            to: headers['to'] ?? message.to ?? '',
            cc: headers['cc'] ?? '',
            subject: headers['subject'] ?? '',
            body_html: bodyHtml,
            body_text: bodyText,
            message_id: headers['message-id'] ?? '',
            source: 'cloudflare',
        });

        const signature = await hmacSha256(payload, env.MAILBOX_SECRET);

        const response = await fetch(env.MAILBOX_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Mailbox-Signature': signature,
            },
            body: payload,
        });

        if (!response.ok) {
            throw new Error(`Mailbox endpoint returned ${response.status}`);
        }
    },
} satisfies ExportedHandler<Env>;
