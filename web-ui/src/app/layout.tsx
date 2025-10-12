import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "../../Providers";
import { LayoutContent } from "../shared/components/layout/LayoutContent";
import { Navbar } from "../shared/components/layout/Navbar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "0G Compute Network Example",
  description: "Web example for 0G Compute Network SDK",
  icons: {
    icon: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <Providers>
          <Navbar />
          <LayoutContent>{children}</LayoutContent>
        </Providers>
      </body>
    </html>
  );
}
