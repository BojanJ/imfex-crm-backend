import { Resend } from 'resend';

const resendApiKey = process.env.RESEND_API_KEY || '';

export const resend = resendApiKey ? new Resend(resendApiKey) : null;
export const EMAIL_FROM = process.env.EMAIL_FROM || 'IMFEX CRM <onboarding@resend.dev>';
export const isEmailConfigured = (): boolean => Boolean(resendApiKey);
