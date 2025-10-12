"use client";

import { Suspense, lazy, type ComponentType, type ReactNode } from "react";

interface PageLoaderProps {
  fallback?: ReactNode;
  children: ReactNode;
}

const DefaultLoadingFallback = () => (
  <div className="w-full h-screen flex items-center justify-center">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-4 border-purple-600 border-t-transparent mx-auto mb-4"></div>
      <p className="text-gray-600 text-sm">Loading page...</p>
    </div>
  </div>
);

const PageContentLoader = () => (
  <div className="w-full min-h-[400px] flex items-center justify-center">
    <div className="text-center">
      <div className="animate-spin rounded-full h-8 w-8 border-3 border-purple-600 border-t-transparent mx-auto mb-3"></div>
      <p className="text-gray-500 text-sm">Loading...</p>
    </div>
  </div>
);

export const PageLoader: React.FC<PageLoaderProps> = ({ 
  fallback = <DefaultLoadingFallback />, 
  children 
}) => (
  <Suspense fallback={fallback}>
    {children}
  </Suspense>
);

export const ContentLoader: React.FC<PageLoaderProps> = ({ 
  fallback = <PageContentLoader />, 
  children 
}) => (
  <Suspense fallback={fallback}>
    {children}
  </Suspense>
);

export function createLazyPage(
  importFn: () => Promise<{ default: ComponentType }>,
  fallback?: ReactNode
) {
  const LazyComponent = lazy(importFn);
  
  return function LazyPageWrapper(props: Record<string, unknown>) {
    return (
      <PageLoader fallback={fallback}>
        <LazyComponent {...props} />
      </PageLoader>
    );
  };
}

export function createLazyComponent(
  importFn: () => Promise<{ default: ComponentType }>,
  fallback?: ReactNode
) {
  const LazyComponent = lazy(importFn);
  
  return function LazyComponentWrapper(props: Record<string, unknown>) {
    return (
      <ContentLoader fallback={fallback}>
        <LazyComponent {...props} />
      </ContentLoader>
    );
  };
}