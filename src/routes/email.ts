import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { resend, EMAIL_FROM } from '../lib/email';
import { AuthenticatedRequest } from '../auth';
import { escapeHtml, isValidEmail, createRateLimiter } from '../security';
import { logger } from '../logger';
import { recordAudit } from '../audit';

const emailLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyPrefix: 'email',
  message: 'Email rate limit exceeded. Please try again shortly.',
});

export const emailRouter = Router();

emailRouter.post('/send-offer', emailLimiter, async (req, res) => {
  try {
    const { to, customerName, offerNumber, totalAmount, pdfBase64, customMessage } = req.body ?? {};

    if (!isValidEmail(to)) {
      return res.status(400).json({ error: 'A valid recipient email address (to) is required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables in Render.',
      });
    }

    const company = await prisma.companySettings.findUnique({ where: { id: 'default' } }).catch(() => null);
    const companyName = company?.companyName || 'ИМФЕКС ЕКСПОРТ-ИМПОРТ ДООЕЛ';
    const companyAddress = company?.address || 'Ул. Качанички Пат бб, Скопје';
    const companyPhone = company?.phone || '+389 2 3123 456';
    const companyEmail = company?.email || 'info@imfex.com';

    const safeCompanyName = escapeHtml(companyName);
    const safeCompanyAddress = escapeHtml(companyAddress);
    const safeCompanyPhone = escapeHtml(companyPhone);
    const safeCompanyEmail = escapeHtml(companyEmail);
    const safeOfferNumber = escapeHtml(offerNumber || '');
    const safeCustomerName = escapeHtml(customerName || 'Клиент');
    const safeCustomMessage = customMessage ? escapeHtml(customMessage) : '';
    const safeAmount = Number.isFinite(Number(totalAmount)) ? Number(totalAmount).toFixed(2) : '0.00';
    const cleanFilename = String(offerNumber || 'Offer').replace(/[^a-zA-Z0-9_-]/g, '_');

    let attachments: { filename: string; content: Buffer }[] = [];
    if (pdfBase64) {
      const cleanBase64 = String(pdfBase64).replace(/^data:.*?;base64,/, '').trim();
      const pdfBuffer = Buffer.from(cleanBase64, 'base64');
      if (!pdfBuffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Invalid PDF attachment.' });
      }
      attachments = [
        {
          filename: `${cleanFilename}.pdf`,
          content: pdfBuffer,
        },
      ];
    }

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e293b; line-height: 1.6;">
        <div style="background-color: #0f172a; padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
          <h1 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 800; letter-spacing: 0.5px;">
            ${safeCompanyName}
          </h1>
          <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 12px;">Комерцијална Понуда • ${safeOfferNumber}</p>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px; font-weight: 700; color: #0f172a;">Почитувани ${safeCustomerName},</p>
          <p style="font-size: 13px; color: #334155;">
            Во прилог на оваа порака Ви ја испраќаме официјалната комерцијална понуда <strong>${safeOfferNumber}</strong> со вкупен износ од <strong>€${safeAmount}</strong>.
          </p>

          ${
            safeCustomMessage
              ? `<div style="background-color: #f8fafc; border-left: 4px solid #2563eb; padding: 12px; margin: 16px 0; font-size: 12px; color: #475569; font-style: italic; white-space: pre-wrap;">
                  "${safeCustomMessage}"
                </div>`
              : ''
          }

          <p style="font-size: 13px; color: #334155;">
            Ве молиме прегледајте го прикачениот PDF документ за детална спецификација на производите и условите за испорака.
          </p>

          <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
            <p style="margin: 0; font-weight: 700;">${safeCompanyName}</p>
            <p style="margin: 2px 0 0 0;">${safeCompanyAddress} | Тел: ${safeCompanyPhone} | Email: ${safeCompanyEmail}</p>
          </div>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [String(to).trim()],
      subject: `Комерцијална Понуда ${String(offerNumber || '').replace(/[\r\n]/g, '')} - ${companyName.replace(/[\r\n]/g, '')}`,
      html: htmlContent,
      attachments,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    logger.error('send_offer_email_error', { error: error?.message || String(error) });
    res.status(500).json({ error: 'Failed to send email.' });
  }
});

// 2. Send Sales Invoice / Dispatch Note PDF to Customer (authenticated, rate-limited, HTML-escaped)
emailRouter.post('/send-invoice', emailLimiter, async (req, res) => {
  try {
    const {
      to,
      customerName,
      invoiceNumber,
      invoiceType,
      totalAmount,
      dueDate,
      pdfBase64,
      customMessage,
    } = req.body ?? {};

    if (!isValidEmail(to)) {
      return res.status(400).json({ error: 'A valid recipient email address (to) is required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables in Render.',
      });
    }

    const company = await prisma.companySettings.findUnique({ where: { id: 'default' } }).catch(() => null);
    const companyName = company?.companyName || 'ИМФЕКС ЕКСПОРТ-ИМПОРТ ДООЕЛ';
    const companyAddress = company?.address || 'Ул. Качанички Пат бб, Скопје';
    const companyPhone = company?.phone || '+389 2 3123 456';
    const companyEmail = company?.email || 'info@imfex.com';
    const companyBankAccount = company?.bankAccount || '';

    const normalizedType = String(invoiceType || 'FINAL').toUpperCase();
    const docTypeLabel =
      normalizedType === 'PROFORMA'
        ? 'Про-Фактура'
        : normalizedType === 'ADVANCE'
        ? 'Авансна Фактура'
        : normalizedType === 'DISPATCH'
        ? 'Испратница'
        : 'Фактура';

    const safeCompanyName = escapeHtml(companyName);
    const safeCompanyAddress = escapeHtml(companyAddress);
    const safeCompanyPhone = escapeHtml(companyPhone);
    const safeCompanyEmail = escapeHtml(companyEmail);
    const safeCompanyBank = companyBankAccount ? escapeHtml(companyBankAccount) : '';
    const safeDocType = escapeHtml(docTypeLabel);
    const safeInvoiceNumber = escapeHtml(invoiceNumber || '');
    const safeCustomerName = escapeHtml(customerName || 'Клиент');
    const safeCustomMessage = customMessage ? escapeHtml(customMessage) : '';
    const safeDueDate = dueDate ? escapeHtml(String(dueDate)) : '';
    const hasAmount = normalizedType !== 'DISPATCH' && Number.isFinite(Number(totalAmount));
    const safeAmount = hasAmount ? Number(totalAmount).toFixed(2) : '';
    const cleanFilename = String(invoiceNumber || 'Invoice').replace(/[^a-zA-Z0-9_-]/g, '_');

    let attachments: { filename: string; content: Buffer }[] = [];
    if (pdfBase64) {
      const cleanBase64 = String(pdfBase64).replace(/^data:.*?;base64,/, '').trim();
      const pdfBuffer = Buffer.from(cleanBase64, 'base64');
      if (!pdfBuffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Invalid PDF attachment.' });
      }
      attachments = [
        {
          filename: `${cleanFilename}.pdf`,
          content: pdfBuffer,
        },
      ];
    }

    const amountSentence = hasAmount
      ? ` со вкупен износ за плаќање од <strong>€${safeAmount}</strong>`
      : '';

    const paymentDetailsHtml =
      normalizedType !== 'DISPATCH' && (safeDueDate || safeCompanyBank)
        ? `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; margin: 16px 0; font-size: 12px; color: #334155;">
            ${safeDueDate ? `<p style="margin: 0 0 4px 0;"><strong>Рок на плаќање:</strong> ${safeDueDate}</p>` : ''}
            ${safeCompanyBank ? `<p style="margin: 0;"><strong>Жиро сметка:</strong> ${safeCompanyBank}</p>` : ''}
          </div>`
        : '';

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e293b; line-height: 1.6;">
        <div style="background-color: #0f172a; padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
          <h1 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 800; letter-spacing: 0.5px;">
            ${safeCompanyName}
          </h1>
          <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 12px;">${safeDocType} • ${safeInvoiceNumber}</p>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px; font-weight: 700; color: #0f172a;">Почитувани ${safeCustomerName},</p>
          <p style="font-size: 13px; color: #334155;">
            Во прилог на оваа порака Ви го испраќаме официјалниот документ <strong>${safeDocType} ${safeInvoiceNumber}</strong>${amountSentence}.
          </p>

          ${paymentDetailsHtml}

          ${
            safeCustomMessage
              ? `<div style="background-color: #f8fafc; border-left: 4px solid #2563eb; padding: 12px; margin: 16px 0; font-size: 12px; color: #475569; font-style: italic; white-space: pre-wrap;">
                  "${safeCustomMessage}"
                </div>`
              : ''
          }

          <p style="font-size: 13px; color: #334155;">
            Ве молиме прегледајте го прикачениот PDF документ. За дополнителни прашања, слободно контактирајте нè.
          </p>

          <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
            <p style="margin: 0; font-weight: 700;">${safeCompanyName}</p>
            <p style="margin: 2px 0 0 0;">${safeCompanyAddress} | Тел: ${safeCompanyPhone} | Email: ${safeCompanyEmail}</p>
          </div>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [String(to).trim()],
      subject: `${docTypeLabel} ${String(invoiceNumber || '').replace(/[\r\n]/g, '')} - ${companyName.replace(/[\r\n]/g, '')}`,
      html: htmlContent,
      attachments,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'INVOICE_EMAIL_SENT',
      entityType: normalizedType === 'DISPATCH' ? 'DispatchNote' : 'SalesInvoice',
      entityId: String(invoiceNumber || ''),
      metadata: { to: String(to).trim(), invoiceType: normalizedType },
    });

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    logger.error('send_invoice_email_error', { error: error?.message || String(error) });
    res.status(500).json({ error: 'Failed to send invoice email.' });
  }
});
