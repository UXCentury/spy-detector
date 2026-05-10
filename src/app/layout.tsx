import type { Metadata, Viewport } from "next";
import { AppGate } from "@/components/AppGate";
import { Providers } from "@/components/Providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Spy Detector",
  description: "Local surveillance-process detection for Windows",
};

export const viewport: Viewport = {
  themeColor: "#0a0a0c",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" style={{ backgroundColor: "#0a0a0c" }}>
      <body
        className="h-dvh overflow-hidden antialiased"
        style={{ backgroundColor: "#0a0a0c" }}
      >
        <Providers>
          <AppGate>{children}</AppGate>
        </Providers>
      </body>
    </html>
  );
}
