import type { Metadata } from "next";
import { Space_Grotesk, Geist_Mono } from "next/font/google";
import { Suspense } from "react";
import "./globals.css";
import { Providers } from "../../Providers";
import { Navbar } from "../shared/components/layout/Navbar";
import { Sidebar } from "../shared/components/layout/Sidebar";
import { LayoutContent } from "../shared/components/layout/LayoutContent";
import { DeprecationBanner } from "../shared/components/layout/DeprecationBanner";
import { Toaster } from "@/components/ui/toaster";

// Space Grotesk as primary font (similar to Regola Pro - geometric sans-serif)
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

// Geist Mono for code, prices, and technical data (per 0G brand kit)
const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "0G Compute Network Example",
  description: "Web example for 0G Compute Network SDK",
  icons: {
    icon: "/favicon.svg",
  },
};

const LayoutLoader = () => (
  <div className="flex h-screen w-full items-center justify-center bg-background">
    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
  </div>
);

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${geistMono.variable}`}>
      <body className="font-sans antialiased">
        <Providers>
          <div className="flex min-h-screen w-full flex-col bg-background">
            <DeprecationBanner />
            <Sidebar />
            <div className="flex flex-col sm:gap-4 sm:py-4 sm:pl-14">
              <Navbar />
              <main className="grid flex-1 items-start gap-4 p-4 sm:px-6 sm:py-0 md:gap-8">
                <Suspense fallback={<LayoutLoader />}>
                  <LayoutContent>{children}</LayoutContent>
                </Suspense>
              </main>
            </div>
          </div>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
