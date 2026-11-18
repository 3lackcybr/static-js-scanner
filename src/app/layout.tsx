import type { Metadata } from 'next';
import { Cinzel, JetBrains_Mono, Plus_Jakarta_Sans } from 'next/font/google';
import './globals.css';

const cinzel = Cinzel({
  subsets: ['latin'],
  weight: ['500', '600', '700'],
  variable: '--font-cinzel',
  display: 'swap',
});

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-jakarta',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-jetbrains',
  display: 'swap',
});

const APP_TITLE = 'Static Vulnerability Scanning Tool';
const APP_DESCRIPTION =
  'A lightweight, web-based static analysis tool that scans JavaScript, HTML, and PHP source code for SQL Injection, XSS, Command Injection, Hardcoded Secrets, and Insecure eval() usage with CWE mapping.';

export const metadata: Metadata = {
  title: APP_TITLE,
  description: APP_DESCRIPTION,
  openGraph: {
    title: APP_TITLE,
    description: APP_DESCRIPTION,
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${cinzel.variable} ${plusJakarta.variable} ${jetbrainsMono.variable}`}
    >
      <body className="cyber-canvas min-h-screen flex flex-col text-slate-200 selection:bg-[#C8A253]/30 selection:text-amber-100">
        {children}
      </body>
    </html>
  );
}
