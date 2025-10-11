"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";



interface OptimizedLinkProps {
  href: string;
  className?: string;
  children: React.ReactNode;
  preload?: boolean;
  onNavigationStart?: () => void;
}

export const OptimizedLink: React.FC<OptimizedLinkProps> = ({
  href,
  className,
  children,
  preload = true,
  onNavigationStart,
}) => {
  const router = useRouter();
  const [isNavigating] = useState(false);

  useEffect(() => {
    if (preload && href !== "#") {
      router.prefetch(href);
    }
  }, [href, preload, router]);

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    
    if (isNavigating) return;
    
    onNavigationStart?.();
    
    router.push(href);
  };

  return (
    <Link 
      href={href} 
      className={className}
      onClick={handleClick}
    >
      {children}
    </Link>
  );
};

// Navigation loading context
import { createContext, useContext } from "react";

interface NavigationContextValue {
  isNavigating: boolean;
  setIsNavigating: (value: boolean) => void;
  targetRoute: string | null;
  setTargetRoute: (route: string | null) => void;
  targetPageType: string | null;
  setTargetPageType: (type: string | null) => void;
}

const NavigationContext = createContext<NavigationContextValue | null>(null);

export const NavigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isNavigating, setIsNavigating] = useState(false);
  const [targetRoute, setTargetRoute] = useState<string | null>(null);
  const [targetPageType, setTargetPageType] = useState<string | null>(null);
  const pathname = usePathname();

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsNavigating(false);
      setTargetRoute(null);
      setTargetPageType(null);
    }, 300);

    return () => clearTimeout(timer);
  }, [pathname]);

  return (
    <NavigationContext.Provider
      value={{
        isNavigating,
        setIsNavigating,
        targetRoute,
        setTargetRoute,
        targetPageType,
        setTargetPageType,
      }}
    >
      {children}
    </NavigationContext.Provider>
  );
};

export const useNavigation = () => {
  const context = useContext(NavigationContext);
  if (!context) {
    throw new Error("useNavigation must be used within NavigationProvider");
  }
  return context;
};
